// Copyright 2025 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

use std::{
    env,
    env::set_var,
    path::{Path, PathBuf},
};

use clap::{
    error::{ContextKind, ContextValue, ErrorKind},
    Arg, ArgAction,
};
use sys_info::cpu_num;
use nix::sys::resource::{setrlimit, Resource};

extern crate libdifuzz;
use libdifuzz::fuzz;

#[cfg(not(test))]
#[allow(clippy::similar_names)]
pub fn main() {
    let matches = clap::Command::new("difuzz_fuzzer_xlnt")
        .version(clap::crate_version!())
        .about("Fuzzer instance for xlnt project.")
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
            Arg::new("sync")
                .short('s')
                .action(ArgAction::Set)
                .value_name("SYNC_DIR")
                .required(false)
                .help("Sync input directory.")
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
            Arg::new("jobs")
                .short('j')
                .action(ArgAction::Set)
                .default_value("1")
                .help("Number of cpu cores to be used by fuzzer.")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("limit")
                .short('l')
                .action(ArgAction::Set)
                .default_value("8")
                .help("Stack limit size in megabytes.")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("iters")
                .long("iters")
                .action(ArgAction::Set)
                .default_value("1000000")
                .help("Number of fuzzer iterations.")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("cool-time")
                .long("cool-time")
                .action(ArgAction::Set)
                .default_value("7200")
                .help("Time (in seconds) to collect coverage.")
                .value_parser(clap::value_parser!(f64)),
        )
        .arg(
            Arg::new("beta")
                .long("beta")
                .action(ArgAction::Set)
                .default_value("0.5")
                .help("Beta parameter for gMaxCov metric.")
                .value_parser(clap::value_parser!(f64)),
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
            Arg::new("forced")
                .long("forced")
                .action(ArgAction::SetTrue)
                .help("All files from sync directory are force-added to corpus.")
        )
        .arg(
            Arg::new("exit-on-all")
                .long("exit-on-all")
                .action(ArgAction::SetTrue)
                .help("Exit fuzzing when all target points are reached.")
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

    let sync_dir = matches.get_one::<PathBuf>("sync");
    let port = matches.get_one::<u16>("port").copied().unwrap();
    let stack_limit = matches.get_one::<u64>("limit").copied().unwrap() * 1024 * 1024;
    let iters = matches.get_one::<u64>("iters").copied().unwrap();
    let forced = matches.get_flag("forced");
    let jobs = matches
        .get_one::<usize>("jobs")
        .copied()
        .unwrap()
        .min(cpu_num().unwrap_or(1) as usize);
    let mut args = if let Some(argv) = matches.get_many::<String>("ARGS") {
        argv.cloned().collect()
    } else {
        Vec::new()
    };

    set_var(
        "ETS_CONFIG_PATH",
        PathBuf::from(matches.get_one::<PathBuf>("ets").unwrap()),
    );

    set_var(
        "EXIT_ON_ALL",
        if matches.get_flag("exit-on-all") {"1"} else {"0"},
    );

    set_var(
        "ETS_COOL_TIME",
        matches.get_one::<f64>("cool-time").unwrap().to_string(),
    );

    set_var(
        "ETS_BETA",
        matches.get_one::<f64>("beta").unwrap().to_string(),
    );

    let bin_path = PathBuf::from(&args[0]);
    args.remove(0);

    if let Err(e) = setrlimit(Resource::RLIMIT_STACK, stack_limit, stack_limit) {
        eprintln!("Error with setting stack size: {}", e);
        return;
    }

    fuzz(
        &[PathBuf::from(matches.get_one::<PathBuf>("input").unwrap())],
        PathBuf::from(matches.get_one::<PathBuf>("crashes").unwrap()),
        bin_path,
        &args,
        sync_dir,
        port,
        jobs,
        forced,
        iters,
    )
    .expect("An error occurred while fuzzing");
}
