use clap::Parser;
use num_bigint::{BigInt, Sign};
use fastcrypto::error::FastCryptoError;
use fastcrypto_vdf::class_group::{Discriminant, QuadraticForm};
use fastcrypto_vdf::ParameterizedGroupElement;
use fastcrypto_vdf::vdf::VDF;
use fastcrypto_vdf::vdf::wesolowski::{ClassGroupVDF, StrongFiatShamir, WesolowskiVDF};

#[derive(Parser)]
#[command(name = "vdf")]
#[command(about = "Evaluate a VDF and create proof", long_about = None)]
enum VDFCommand {
    /// Generate a discriminant for a class group based on an arbitrary binary seed.
    Generate(GenerateArguments),

    /// Evaluate a VDF.
    Evaluate(EvaluateArguments),

    /// Verify the output and proof of a VDF.
    Verify(VerifyArguments),
}

#[derive(Parser, Clone)]
struct GenerateArguments {

    /// The binary seed as a hex string.
    #[clap(short, long)]
    seed: String,

    /// The number of bits in the target discriminant.
    #[clap(short, long)]
    bits: u64,
}

#[derive(Parser, Clone)]
struct EvaluateArguments {

    /// The absolute value of the discriminant of the imaginary class group as a big-endian hex string.
    #[clap(short, long)]
    discriminant: String,

    /// The number of iterations to compute.
    #[clap(long)]
    iterations: u64,

    /// The input to the VDF in compressed form as a hex string. If not specified the quadratic form (2, 1, _) is used.
    #[clap(long, default_value = "") ]
    input: String,

    #[clap(long, default_value = "s")]
    fiat_shamir: String
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    #[clap(short, long)]
    discriminant: String,

    #[clap(short, long)]
    iterations: u64,

    #[clap(short, long)]
    output: String,

    #[clap(short, long)]
    proof: String,

}

fn main() {
    match execute(VDFCommand::parse()) {
        Ok(_) => {
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

fn execute(command: VDFCommand) -> Result<(), FastCryptoError> {
    match command {
        VDFCommand::Evaluate(arguments) => {
            let discriminant_bytes = hex::decode(&arguments.discriminant).map_err(|_| FastCryptoError::InvalidInput)?;
            let discriminant_big_int = BigInt::from_bytes_be(Sign::Minus, &discriminant_bytes);
            let discriminant = Discriminant::try_from(discriminant_big_int)?;
            let vdf = ClassGroupVDF::new(discriminant.clone(), arguments.iterations);

            let input_point = if arguments.input.is_empty() {
                QuadraticForm::generator(&discriminant)
            } else {
                QuadraticForm::from_bytes(&hex::decode(arguments.input).map_err(|_| FastCryptoError::InvalidInput)?, &discriminant)?
            };

            let (output, proof) = vdf.evaluate(&input_point)?;

            println!("Output : {}", hex::encode(output.as_bytes()));
            println!("Proof  : {}", hex::encode(proof.as_bytes()));
            Ok({})
        },

        VDFCommand::Generate(arguments) => {
            let seed = hex::decode(arguments.seed).map_err(|_| FastCryptoError::InvalidInput)?;
            let discriminant = Discriminant::from_seed(&seed, arguments.bits as usize)?;
            println!("Discriminant: {}", hex::encode(discriminant.to_bytes()));
            Ok({})
        },

        VDFCommand::Verify(_) => Ok({})
    }
}