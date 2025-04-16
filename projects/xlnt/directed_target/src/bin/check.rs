use std::{env, path::PathBuf, path::Path, env::set_var};

use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};

extern crate libdifuzz;
use libdifuzz::fuzz_one;

// #[cfg(not(test))]
#[allow(clippy::similar_names)]
pub fn main() {
    let matches = clap::Command::new("difuzz_check_xlnt")
        .version(clap::crate_version!())
        .about("Fuzzer binary for checking reached target points for xlnt project.")
        .term_width(90)
        .arg(
            Arg::new("input")
                .short('i')
                .action(ArgAction::Set)
                .value_name("INPUT_DIR")
                .help("Input corpus directory.")
                .default_value("./corpus")
                .value_parser(move |arg: &str| {
                    let corpus = Path::new(arg);
                    if !corpus.exists() {
                        let mut err = clap::Error::new(ErrorKind::ValueValidation);
                        err.insert(
                            ContextKind::InvalidValue,
                            ContextValue::String("Corpus directory doesn't exist.".to_owned()),
                        );
                        return Err(err);
                    }
                    Ok(corpus.to_path_buf())
                }),
        )
        .arg(
            Arg::new("crashes")
                .short('x')
                .action(ArgAction::Set)
                .value_name("CRASH_DIR")
                .help("Output directory with crashes.")
                .default_value("./crashes")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("ets")
                .short('e')
                .action(ArgAction::Set)
                .value_name("ETS_PATH")
                .help("Path to ets.toml.")
                .default_value("./ets.toml")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .action(ArgAction::Set)
                .default_value("1337")
                .help("Broker port.")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("input_file")
                .short('f')
                .long("input_file")
                .action(ArgAction::Set)
                .value_name("INPUT_FILE")
                .help("Input file to check.")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("ARGS")
                .action(ArgAction::Set)
                .required(true)
                .num_args(1..)
                .last(true)
                .help("Add \"-- /path/to/target_bin <arguments>\" to set binary path and its arguments.")
        )
        .get_matches();

    let port = matches.get_one::<u16>("port").copied().unwrap();
    let mut args = if let Some(argv) = matches.get_many::<String>("ARGS") {
        argv.cloned().collect()
    } else {
        Vec::new()
    };

    set_var("ETS_CONFIG_PATH", PathBuf::from(matches.get_one::<PathBuf>("ets").unwrap()));

    let bin_path = PathBuf::from(&args[0]);
    args.remove(0);

    fuzz_one(
        &[PathBuf::from(matches.get_one::<PathBuf>("input").unwrap())],
        PathBuf::from(matches.get_one::<PathBuf>("crashes").unwrap()),
        bin_path,
        &args,
        port,
        PathBuf::from(matches.get_one::<PathBuf>("input_file").unwrap()),
    )
    .expect("An error occurred while fuzzing");
}
