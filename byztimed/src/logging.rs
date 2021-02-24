//Copyright 2021, Akamai Technologies, Inc.
//SPDX-License-Identifier: Apache-2.0

//! Configuration for log4rs
//!
//! log4rs is a very flexible logging framework – much more flexible than we need it to be.
//! This module translates the much simpler configuration language we expose through the
//! Byztime config file into a log4rs configuration and initializes log4rs accordingly.

use log4rs::append::console::Target;
use log4rs::config::*;
use log4rs::encode::pattern::PatternEncoder;
use std::boxed::Box;
use std::fmt;
use std::io;
use std::path;

pub type LogHandle = log4rs::Handle;

///A logging target — either a file or STDOUT or STDERR — coupled with
/// a minimum severity level
pub enum LogConfig {
    ConsoleLog(Target, log::LevelFilter),
    FileLog(path::PathBuf, log::LevelFilter),
}

//log4rs is missing derived traits for Target, so we have to manually reimplement this.
fn clone_target(target: &Target) -> Target {
    match target {
        Target::Stdout => Target::Stdout,
        Target::Stderr => Target::Stderr,
    }
}

impl LogConfig {
    fn name(&self) -> &str {
        match self {
            LogConfig::ConsoleLog(target, _) => match target {
                Target::Stdout => "STDOUT",
                Target::Stderr => "STDERR",
            },
            LogConfig::FileLog(path, _) => path.to_str().expect("malformed UTF-8 in path name"),
        }
    }

    fn level(&self) -> log::LevelFilter {
        match self {
            LogConfig::ConsoleLog(_, level) => *level,
            LogConfig::FileLog(_, level) => *level,
        }
    }

    fn filter(&self) -> Box<dyn log4rs::filter::Filter> {
        Box::new(log4rs::filter::threshold::ThresholdFilter::new(
            self.level(),
        ))
    }

    fn append(&self, pattern: Option<&str>) -> io::Result<Box<dyn log4rs::append::Append>> {
        match self {
            LogConfig::ConsoleLog(target, _) => Ok(Box::new(
                log4rs::append::console::ConsoleAppender::builder()
                    .target(clone_target(target))
                    .encoder(Box::new(PatternEncoder::new(
                        pattern.unwrap_or("{d} {l} {t} - {m}{n}"),
                    )))
                    .build(),
            )),
            LogConfig::FileLog(path, _) => Ok(Box::new(
                log4rs::append::file::FileAppender::builder()
                    .encoder(Box::new(PatternEncoder::new(
                        pattern.unwrap_or("{d} {l} {t} - {m}{n}"),
                    )))
                    .build(path)?,
            )),
        }
    }

    fn appender(&self, pattern: Option<&str>) -> io::Result<Appender> {
        Ok(Appender::builder()
            .filter(self.filter())
            .build(self.name(), self.append(pattern)?))
    }
}

//`Target` is missing a derived `Debug` trait so for `LogConfig` we have to implement
// `Debug` manually rather than deriving it.
impl fmt::Debug for LogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogConfig::ConsoleLog(Target::Stdout, level) => {
                write!(f, "ConsoleLog(Stdout, {:?})", level)
            }
            LogConfig::ConsoleLog(Target::Stderr, level) => {
                write!(f, "ConsoleLog(Stderr, {:?})", level)
            }
            LogConfig::FileLog(path, level) => write!(f, "FileLog({:?}, {:?})", path, level),
        }
    }
}

//Ditto for `Clone`.
impl Clone for LogConfig {
    fn clone(&self) -> LogConfig {
        match self {
            LogConfig::ConsoleLog(target, filter) => {
                LogConfig::ConsoleLog(clone_target(target), *filter)
            }
            LogConfig::FileLog(path, filter) => LogConfig::FileLog(path.clone(), *filter),
        }
    }
}

///Build a log4rs config from a sequence of `LogConfig`s returned by the iterator
fn build_config<'a, I: IntoIterator<Item = &'a LogConfig>>(
    cfgs: I,
    pattern: Option<&str>,
) -> io::Result<Config> {
    let mut config_builder = Config::builder();
    let mut root_builder = Root::builder();
    for cfg in cfgs.into_iter() {
        config_builder = config_builder.appender(cfg.appender(pattern)?);
        root_builder = root_builder.appender(cfg.name());
    }
    let root = root_builder.build(log::LevelFilter::Trace);
    Ok(config_builder
        .build(root)
        .expect("While building log config"))
}

///Initialize logging
pub fn init_logging<'a, I: IntoIterator<Item = &'a LogConfig>>(
    cfgs: I,
    pattern: Option<&str>,
) -> io::Result<LogHandle> {
    Ok(log4rs::init_config(build_config(cfgs, pattern)?).expect("While initializing logging"))
}

///Reinitialize logging (useful for reopening log files after they've been rotated)
pub fn reinit_logging<'a, I: IntoIterator<Item = &'a LogConfig>>(
    cfgs: I,
    pattern: Option<&str>,
    handle: &LogHandle,
) -> io::Result<()> {
    handle.set_config(build_config(cfgs, pattern)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::info;
    use std::fs;

    //This test is broken. Its intent is to check that log rotation
    // works, but it panics on init_logging() because cargo's unit
    // test framework has already initialized logging before our unit
    // test ever gets invoked. There's currently no way to fix this,
    // but we can keep the code around in case there ever is. For now
    // there's no #[test] attribute on this function, so it won't be
    // run.
    #[allow(dead_code)]
    fn log_rotation() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let mut logpath = path::PathBuf::from(tempdir.path());
        let mut logpath_rotated = logpath.clone();
        logpath.push("logfile");
        logpath_rotated.push("logfile.old");
        let logconfig = vec![LogConfig::FileLog(logpath.clone(), log::LevelFilter::Info)];
        let handle = init_logging(&logconfig, None).unwrap();
        info!("PRE-ROTATION");
        fs::rename(&logpath, &logpath_rotated).unwrap();
        info!("MID-ROTATION");
        reinit_logging(&logconfig, None, &handle).unwrap();
        info!("POST-ROTATION");

        //Here we would check for the strings "PRE-ROTATION" and
        // "MID-ROTATION" in logfile.old, and "POST-ROTATION" in
        // logfile.
    }
}
