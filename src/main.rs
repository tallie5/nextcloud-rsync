#![feature(vec_remove_item)]

extern crate chrono;
extern crate curl;
extern crate fxhash;
extern crate percent_encoding;
extern crate quick_xml;
extern crate rayon;
extern crate rpassword;
extern crate url;
extern crate walkdir;

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;
use std::str;
use std::sync::mpsc::channel;

use curl::easy::{Easy2, Easy, List, Handler, WriteError};
use fxhash::FxHashMap;
use quick_xml::Reader;
use quick_xml::events::Event;
use rayon::prelude::*;
use percent_encoding::percent_decode;
use walkdir::WalkDir;


fn main() {
  const VERSION: &'static str = env!("CARGO_PKG_VERSION");

  let args: Vec<String> = env::args().collect();

  if args.len() < 3 {
    println!("nextcloud-rsync requires at least 2 arguments.  You supplied {}.", args.len()-1);
    process::exit(1);
  }

  let mut arg_delete = false;
  let mut arg_links = false;
  let mut arg_threads = "0";
  let mut arg_threads_position = 0;
  let mut arg_verbose = false;
  let mut arg_local = false;
  let mut arg_local_path = "";
  let mut local_path_counter = 0;
  let mut local_path_position = 0;
  let mut arg_cloud = false;
  let mut arg_cloud_path = "";
  let mut cloud_path_counter = 0;
  let mut cloud_path_position = 0;
  let mut arg_count = 1;

  for arg in args.iter().skip(1) {
    if arg == "--delete" || arg == "-d" {
      arg_delete = true;
    } else if arg == "--ignore-links" || arg == "-l" {
      arg_links = true;
    } else if arg.starts_with("--parallel=") {
      let arg_vec: Vec<&str> = arg.split('=').collect();
      if !arg_vec[1].contains(char::is_alphabetic) && arg_vec[1].contains(char::is_numeric) {
        arg_threads = arg_vec[1];
      } else {
        println!("--parallel argument format: --parallel=[0-9]");
        process::exit(1);
      }
    } else if arg == "-p" {
      let position = args.iter().position(|x| x == "-p").unwrap();
      let next = position + 1;
      arg_threads_position = next;
      arg_threads = args.iter().nth(next).unwrap();
    } else if arg.starts_with("-p") {
      let arg_vec: Vec<&str> = arg.split('p').collect();
      if !arg_vec[1].contains(char::is_alphabetic) && arg_vec[1].contains(char::is_numeric) {
        arg_threads = arg_vec[1];
      }
    } else if arg == "--verbose" || arg == "-v" {
      arg_verbose = true;
    } else if arg == "--version" || arg == "-V" {
      println!("{}", VERSION);
      process::exit(0);
    } else if !arg.starts_with("--") && !arg.starts_with("~~/") && arg_threads_position != arg_count {
      local_path_counter = local_path_counter + 1;
      if arg.starts_with("~~") {
        println!("Nextcloud path must begin with '/'.");
        process::exit(1);
      }
      if local_path_counter > 1 {
        println!("Only one local directory may be specified.");
        process::exit(1);
      }
      arg_local = true;
      arg_local_path = arg.trim_end_matches("/");
      local_path_position = args.iter().position(|x| x == arg).unwrap();
    } else if arg.starts_with("~~/") {
      cloud_path_counter = cloud_path_counter + 1;
      if cloud_path_counter > 1 {
        println!("Only one cloud directory may be specified.");
        process::exit(1);
      }
      arg_cloud = true;
      arg_cloud_path = arg.trim_end_matches("/");
      cloud_path_position = args.iter().position(|x| x == arg).unwrap();
    } else {
      if arg_threads_position == arg_count {
        arg_count += 1;
        continue;
      }
      println!("Unrecognized argument {}.", arg);
      process::exit(1);
    }
    arg_count += 1;
  }

  rayon::ThreadPoolBuilder::new().num_threads(arg_threads.parse::<usize>().unwrap()).build_global().unwrap();

  if arg_local == false || arg_cloud == false {
    println!("A source and destination must be specified.");
    process::exit(1);
  }

  let source_path;

  let local_path = Path::new(arg_local_path);
  let cloud_path = arg_cloud_path.to_string().split_off(3);

  if local_path_position < cloud_path_position {
    source_path = arg_local_path;
  } else {
    source_path = arg_cloud_path;
  }

  // Make sure local path is valid if source.
  let mut local_is_dir = false;
  let mut local_exists = true;

  if local_path.is_dir() {
    local_is_dir = true;
  } else if !local_path.exists() {
    local_exists = false;
  } else if source_path == arg_local_path {
    println!("Local path {:?} is invalid.", local_path);
    process::exit(1);
  } else if local_path.exists() {
    println!("Local path {:?} is not a directory.", local_path);
    process::exit(1);
  }

  // Create config directory.
  let cookie_location;
  let env_cookie_location = "NEXTCLOUD_COOKIE";
  let user_cookie_location = match env::var_os(env_cookie_location) {
    Some(val) => val.into_string().unwrap(),
    None => OsStr::new("").to_os_string().into_string().unwrap(),
  };
  if fs::metadata(user_cookie_location.clone()).is_ok() {
    cookie_location = user_cookie_location;
  } else {
    cookie_location = match env::var_os("HOME") {
      Some(val) => val.into_string().unwrap(),
      None => OsStr::new("").to_os_string().into_string().unwrap(),
    };
  }
  let config_dir = format!("{}/.config/nextcloud-rsync", cookie_location);
  match fs::create_dir_all(&config_dir) {
    Err(e) => println!("Encountered error while attempting to create {}: {}\nCookies will not be stored.", config_dir, e),
    Ok(val) => val,
  };
  let mut cookie_mode = false;
  let cookie_file = format!("{}/cookie", &config_dir);
  let cookie_file_path = cookie_file.as_str();
  if Path::new(&config_dir).exists() {
    if Path::new(&cookie_file).exists() {
      cookie_mode = true;
    } else {
      match File::create(&cookie_file) {
        Err(_e) => false,
        Ok(_val) => true,
      };
      if Path::new(&cookie_file).exists() {
        cookie_mode = true;
      }
    }
  }

  // Validate env variables.
  let env_cloud_url = "NEXTCLOUD_URL";
  let env_cloud_user = "NEXTCLOUD_USER";
  let env_cloud_password = "NEXTCLOUD_PASSWORD";

  let cloud_url = match env::var(env_cloud_url) {
    Err(e) => panic!("error reading {}: {}", env_cloud_url, e),
    Ok(val) => val,
  };
  let cloud_user = match env::var(env_cloud_user) {
    Err(e) => panic!("error reading {}: {}", env_cloud_user, e),
    Ok(val) => val,
  };
  let mut cloud_password = match env::var_os(env_cloud_password) {
    Some(val) => val.into_string().unwrap(),
    None => OsStr::new("").to_os_string().into_string().unwrap(),
  };

  // Test authentication to Nextcloud. If cookies are expired, then create new cookies.
  if cloud_exec_auth(&cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, "authcheck") == false {
    match fs::remove_file(&cookie_file) {
      Err(e) => println!("Encountered error while attempting to remove {}: {}.", &cookie_file, e),
      Ok(val) => val,
    };
    if cloud_password == "" {
      cloud_password = rpassword::prompt_password_stdout("Password: ").unwrap();
    } else {
      println!("Could not authenticate with provided password.");
      process::exit(1);
    }
    if cloud_exec_auth(&cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, "auth") == false {
      println!("Could not authenticate with provided password.");
      process::exit(1);
    }
  }

  // Test if the cloud directory exists, if it is the source.
  let mut cloud_is_source = false;
  if source_path == arg_cloud_path {
    cloud_is_source = true;
  }
  let cloud_prefix_count = cloud_exec_url_count(&cloud_path, &cloud_user);
  let cloud_list_tuple = cloud_exec_list(cloud_is_source, cloud_prefix_count, &cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, local_is_dir); 
  let cloud_dirs_vec = cloud_list_tuple.0;
  let cloud_files_hashmap = cloud_list_tuple.1;
  if cloud_is_source {
    if cloud_dirs_vec.is_empty() && cloud_files_hashmap.is_empty() {
      println!("Source path: \"{}\" does not exist.", arg_cloud_path);
      process::exit(1);
    }
  } else if cloud_dirs_vec.is_empty() && cloud_files_hashmap.is_empty() && local_is_dir && !cloud_is_source {
    // If source is local and a directory, create root directory.
    let cloud_path_components: Vec<&str> = cloud_path.split('/').collect();
    let mut cloud_root_vec: Vec<_> = Vec::new();
    for component in cloud_path_components {
      if cloud_root_vec.is_empty() {
        cloud_root_vec.push(component.to_string());
      } else {
        let last_dir = cloud_root_vec.last().unwrap();
        let new_dir = format!("{}/{}", last_dir, component);
        cloud_root_vec.push(new_dir);
      }
    }
    for directory in cloud_root_vec {
        let cloud_tmp_vec: Vec<&std::string::String> = vec![&directory];
        cloud_exec_dir(cloud_is_source, "", &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, &cloud_tmp_vec, local_is_dir, "root");
    }
  }

  if arg_verbose == true {
    println!("cloud_dirs_vec {:?}", cloud_dirs_vec);
    println!("cloud_files_hashmap {:?}", cloud_files_hashmap);
  }
  let mut local_dirs_vec = Vec::new();
  let mut local_files_hashmap = FxHashMap::default();
  let local_list;

  // If the dir exists, add its contents to the tuple, otherwise create the directory structure.
  if local_is_dir && local_exists {
    if arg_links {
      local_list = WalkDir::new(&local_path).min_depth(1);
    } else {
      local_list = WalkDir::new(&local_path).follow_links(true).min_depth(1);
    }
    let local_list_tuple = local_exec_list(arg_local_path, local_list);
    local_dirs_vec = local_list_tuple.0;
    local_files_hashmap = local_list_tuple.1;
  } else if !local_exists {
    match fs::create_dir_all(&local_path) {
      Err(e) => println!("Encountered error while attempting to create {:?}: {}.", &local_path, e),
      Ok(val) => val,
    };
  } else {
    println!("Abnormal case detected. Local path must be directory or nonexistent");
    process::exit(1);
  }
  if arg_verbose == true {
    println!("local_dir_vec {:?}", local_dirs_vec);
    println!("local_files_hashmap {:?}", local_files_hashmap);
  }

  let destination_dirs_vec;
  let destination_files_hashmap;
  let source_dirs_vec;
  let source_files_hashmap;

  if !cloud_is_source {
    source_dirs_vec = local_dirs_vec;
    source_files_hashmap = local_files_hashmap;
    destination_dirs_vec = cloud_dirs_vec;
    destination_files_hashmap = cloud_files_hashmap;
  } else {
    source_dirs_vec = cloud_dirs_vec;
    source_files_hashmap = cloud_files_hashmap;
    destination_dirs_vec = local_dirs_vec;
    destination_files_hashmap = local_files_hashmap;
  }

  let (sender, receiver) = channel();

  source_dirs_vec.par_iter().for_each_with(sender, |p, x|
    if !destination_dirs_vec.contains(&*x) {
      p.send(x).unwrap();
    }
  );

  let mut create_dirs_vec: Vec<_> = receiver.iter().collect();
  create_dirs_vec.sort_unstable();
  let (sender, receiver) = channel();

  source_files_hashmap.par_iter().for_each_with(sender, |p, x|
    if destination_files_hashmap.contains_key(&*x.0) {
      if destination_files_hashmap.get(&*x.0) != source_files_hashmap.get(&*x.0) {
        p.send(x.0).unwrap();
      }
    } else {
      p.send(x.0).unwrap();
    }
  );

  let update_files_vec: Vec<_> = receiver.iter().collect();

  let mut delete_dirs_vec = Vec::new();
  let mut delete_files_vec = Vec::new();

  if arg_delete == true {
    let (sender, receiver) = channel();

    destination_dirs_vec.par_iter().for_each_with(sender, |p, x|
      if !source_dirs_vec.contains(&*x) {
        p.send(x).unwrap();
      }
    );
    delete_dirs_vec = receiver.iter().collect();
    delete_dirs_vec.sort_unstable();
    delete_dirs_vec.dedup_by(|a, b| a.as_str().starts_with(b.as_str()));
  }

  if arg_delete == true {
    let (sender, receiver) = channel();

    destination_files_hashmap.par_iter().for_each_with(sender, |p, x|
      if !source_files_hashmap.contains_key(&*x.0) {
        p.send(x.0).unwrap();
      }
    );
    delete_files_vec = receiver.iter().collect();
  }

  if arg_delete == true {
    let (sender, receiver) = channel();

    destination_files_hashmap.par_iter().for_each_with(sender, |p, x|
      for dir in &delete_dirs_vec {
        if x.0.starts_with(dir.as_str()) {
          p.send(x.0).unwrap();
        }
      }
    );
    let redundant_files_vec: Vec<_> = receiver.iter().collect();
    for file in redundant_files_vec {
      delete_files_vec.remove_item(&file);
    }
  }

  if arg_verbose == true {
    println!("create_dirs_vec {:?}", create_dirs_vec);
    println!("delete_dirs_vec {:?}", delete_dirs_vec);
    println!("update_files_vec {:?}", update_files_vec);
    println!("delete_files_vec {:?}", delete_files_vec);
  }

  if source_path == arg_local_path {
    if arg_delete == true {
      cloud_exec_mod(arg_local_path, cloud_is_source, &cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, &delete_dirs_vec, local_is_dir, "delete");
      cloud_exec_mod(arg_local_path, cloud_is_source, &cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, &delete_files_vec, local_is_dir, "delete");
    }
    cloud_exec_dir(cloud_is_source, &cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, &create_dirs_vec, local_is_dir, "dir");
    cloud_exec_mod(arg_local_path, cloud_is_source, &cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, &update_files_vec, local_is_dir, "put");
  } else if source_path == arg_cloud_path {
    if arg_delete == true {
      local_exec_mod(arg_local_path, &delete_dirs_vec, "delete_dir");
      local_exec_mod(arg_local_path, &delete_files_vec, "delete_files");
    }
    local_exec_mod(arg_local_path, &create_dirs_vec, "create_dir");
    cloud_exec_get(arg_local_path, &cloud_path, &cloud_password, &cloud_url, &cloud_user, cookie_mode, &cookie_file_path, &update_files_vec); 
  }
}

fn local_exec_list(local_path: &str, local_list: WalkDir) -> (Vec<String>, FxHashMap<String,u64>) {
  let mut local_dirs_vec = Vec::new();
  let mut local_files_hashmap = FxHashMap::default();
  let mut local_file_variable;
  let mut count = local_path.to_string().capacity();
  count += 1;
  for entry in local_list {
    let path = entry.unwrap().path().to_owned();
    let mut path_string = path.to_str().unwrap().to_string().split_off(count);
    if path.is_dir() {
      path_string = format!("{}/", path_string);
      local_dirs_vec.push(path_string);
    } else {
      local_file_variable = fs::metadata(&path).unwrap().len();
      local_files_hashmap.insert(path_string, local_file_variable);
    }
  }
  return (local_dirs_vec, local_files_hashmap);
}

fn local_exec_mod(arg_local_path: &str, dirs_vec: &Vec<&String>, mode: &str) -> bool {
  dirs_vec.par_iter().for_each(|element|
    if true {
    let element_string = format!("{}/{}", arg_local_path, *element);
    let element_path = Path::new(&element_string);
    if mode == "create_dir" {
      match fs::create_dir_all(element_path) {
        Err(e) => println!("Encountered error while attempting to create {}: {}.", element_string, e),
        Ok(val) => val,
      };
    } else if mode == "delete_dir" {
      match fs::remove_dir_all(element_path) {
        Err(e) => println!("Encountered error while attempting to remove {}: {}.", element_string, e),
        Ok(val) => val,
      };
    } else if mode == "delete_files" {
      match fs::remove_file(element_path) {
        Err(e) => println!("Encountered error while attempting to remove {}: {}.", element_string, e),
        Ok(val) => val,
      };
    }
    }
  );
  return true;
}

fn cloud_exec_auth(cloud_path: &str, cloud_password: &str, cloud_url: &str, cloud_user: &str, cookie_mode: bool, cookie_file: &str, mode: &str) -> bool {
  struct Collector(Vec<u8>);

  impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
      self.0.extend_from_slice(data);
      Ok(data.len())
    }
  }

  if mode == "auth" || mode == "authcheck" {
    let url = cloud_exec_url(&cloud_path, &cloud_url, &cloud_user, "list");
    let mut easy = Easy2::new(Collector(Vec::new()));
    easy.url(&url).unwrap();
    easy.get(true).unwrap();
    let header = format!("OCS-APIRequest: true");
    let mut list = List::new();
    list.append(&header).unwrap();
    if mode == "auth" {
      easy.username(&cloud_user).unwrap();
      easy.password(&cloud_password).unwrap();
    }
    if cookie_mode == true {
      easy.cookie_file(&cookie_file).unwrap();
      easy.cookie_jar(&cookie_file).unwrap();
    } else if mode == "authcheck" {
      easy.username(&cloud_user).unwrap();
      easy.password(&cloud_password).unwrap();
    }
    easy.http_headers(list).unwrap();
    easy.perform().unwrap();
    if easy.response_code().unwrap() == 401 {
      return false;
    }
    easy.perform().unwrap();
    if easy.response_code().unwrap() == 401 {
      return false;
    }
    return true;
  } else {
    return false;
  }
}

fn cloud_exec_get(arg_local_path: &str, cloud_path: &str, cloud_password: &str, cloud_url: &str, cloud_user: &str, cookie_mode: bool, cookie_file: &str, files_vec: &Vec<&String>) -> bool {
  struct Collector(Vec<u8>);

  impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
      self.0.extend_from_slice(data);
      Ok(data.len())
    }
  }

  let url = cloud_exec_url(&cloud_path, &cloud_url, &cloud_user, "mod");

  files_vec.par_iter().for_each(|element|
    if true {
    let mut easy = Easy2::new(Collector(Vec::new()));
    let file_url = format!("{}/{}", url, *element);
    easy.url(&file_url).unwrap();
    let header = format!("OCS-APIRequest: true");
    let mut list = List::new();
    list.append(&header).unwrap();
    if cookie_mode {
      easy.cookie_file(cookie_file).unwrap();
      easy.cookie_jar(cookie_file).unwrap();
    } else {
      easy.username(&cloud_user).unwrap();
      easy.password(&cloud_password).unwrap();
    }
    easy.http_headers(list).unwrap();
    easy.perform().unwrap();
    let contents = easy.get_ref();
    let file_path = format!("{}/{}", arg_local_path, *element);
    let mut file = File::create(file_path).unwrap();
    file.write_all(String::from_utf8_lossy(&contents.0).as_bytes()).unwrap();
    }
  );
  return true;
}

fn cloud_exec_dir(cloud_is_source: bool, cloud_path: &str, cloud_password: &str, cloud_url: &str, cloud_user: &str, cookie_mode: bool, cookie_file: &str, element_vec: &Vec<&String>, local_is_dir: bool, mode: &str) -> bool {
  let url = cloud_exec_url(&cloud_path, &cloud_url, &cloud_user, "mod");

  for element in element_vec {
    let mut easy = Easy::new();
    let mut file_url = format!("{}/{}", url, *element);
    if cloud_is_source == false && local_is_dir == false {
      let slash_index = &element.to_string().rfind("/").unwrap();
      let file_element = &element.to_string().split_off(*slash_index);
      file_url = format!("{}{}", url, file_element);
    }
    easy.url(&file_url).unwrap();
    if mode == "dir" || mode == "root" {
      easy.custom_request("MKCOL").unwrap();
    } else {
      println!("Mode specified: {} is invalid.", mode);
      process::exit(1);
    }
    let header = format!("OCS-APIRequest: true");
    let mut list = List::new();
    list.append(&header).unwrap();
    if cookie_mode == true {
      easy.cookie_file(cookie_file).unwrap();
      easy.cookie_jar(cookie_file).unwrap();
    } else {
      easy.username(&cloud_user).unwrap();
      easy.password(&cloud_password).unwrap();
    }
    easy.http_headers(list).unwrap();
    if mode == "dir" || mode == "root" {
      easy.perform().expect("Failed to perform cloud operation.");
    }
    if easy.response_code().unwrap() != 201 && easy.response_code().unwrap() != 204 {
      println!("Warning: Request did not return a 201 or 204, please check that the paths exist.");
      println!("response code: {}", easy.response_code().unwrap());
      println!("element: {}", element);
      println!("mode: {}", mode);
    }
  };
  return true;
}

fn cloud_exec_mod(arg_local_path: &str, cloud_is_source: bool, cloud_path: &str, cloud_password: &str, cloud_url: &str, cloud_user: &str, cookie_mode: bool, cookie_file: &str, element_vec: &Vec<&String>, local_is_dir: bool, mode: &str) -> bool {
  let url = cloud_exec_url(&cloud_path, &cloud_url, &cloud_user, "mod");

  element_vec.par_iter().for_each(|element|
    if true {
    let mut easy = Easy::new();
    let mut file_url = format!("{}/{}", url, *element);
    if cloud_is_source == false && local_is_dir == false {
      let slash_index = &element.to_string().rfind("/").unwrap();
      let file_element = &element.to_string().split_off(*slash_index);
      file_url = format!("{}{}", url, file_element);
    }
    easy.url(&file_url).unwrap();
    if mode == "put" {
      easy.put(true).unwrap();
    } else if mode == "delete" {
      easy.custom_request("DELETE").unwrap();
    } else {
      println!("Mode specified: {} is invalid.", mode);
      process::exit(1);
    }
    let header = format!("OCS-APIRequest: true");
    let mut list = List::new();
    list.append(&header).unwrap();
    if cookie_mode == true {
      easy.cookie_file(cookie_file).unwrap();
      easy.cookie_jar(cookie_file).unwrap();
    } else {
      easy.username(&cloud_user).unwrap();
      easy.password(&cloud_password).unwrap();
    }
    easy.http_headers(list).unwrap();
    if mode == "put" {
      let mut file_path = format!("{}/{}", arg_local_path, *element);
      if cloud_is_source == false && local_is_dir == false {
        file_path = format!("{}", arg_local_path);
      }
      let mut file = File::open(file_path).unwrap();
      let mut transfer = easy.transfer();
      transfer.read_function(|buf| {
        Ok(file.read(buf).unwrap_or(0))
      }).unwrap();
      transfer.perform().unwrap();
    }
    if mode == "delete" {
      easy.perform().expect("Failed to perform cloud operation.");
    }
    if easy.response_code().unwrap() != 201 && easy.response_code().unwrap() != 204 {
      println!("Warning: Request did not return a 201 or 204, please check that the paths exist.");
      println!("response code: {}", easy.response_code().unwrap());
      println!("element: {}", element);
      println!("mode: {}", mode);
    }
    }
  );
  return true;
}

fn cloud_exec_list(cloud_is_source: bool, cloud_prefix_count: usize, cloud_path: &str, cloud_password: &str, cloud_url: &str, cloud_user: &str, cookie_mode: bool, cookie_file: &str, local_is_dir: bool) -> (Vec<String>, FxHashMap<String,u64>)  {
  struct Collector(Vec<u8>);

  impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
      self.0.extend_from_slice(data);
      Ok(data.len())
    }
  }

  let mut dir_queue = Vec::new();
  let mut count = 0;
  let mut url;

  let mut dirs = Vec::new();
  let mut files = FxHashMap::default();

  loop {
    if count != 0 {
      if dir_queue.is_empty() {
        break;
      }
      url = format!("{}{}", &cloud_url, dir_queue.pop().unwrap());
    } else {
      url = cloud_exec_url(&cloud_path, &cloud_url, &cloud_user, "list");
    }
    let mut easy = Easy2::new(Collector(Vec::new()));
    easy.url(&url).unwrap();
    easy.custom_request("PROPFIND").unwrap();
    easy.post(true).unwrap();
    let data = format!(r#"<?xml version="1.0" encoding="UTF-8"?><d:propfind xmlns:d="DAV:"><d:prop xmlns:oc="http://owncloud.org/ns"><d:getcontentlength/></d:prop></d:propfind>"#);
    match easy.post_fields_copy(data.as_bytes()) {
      Err(e) => println!("Encountered error: {}.", e),
      Ok(val) => val,
    }
    let header = format!("OCS-APIRequest: true");
    let mut list = List::new();
    list.append(&header).unwrap();
    if cookie_mode == true {
      easy.cookie_file(cookie_file).unwrap();
      easy.cookie_jar(cookie_file).unwrap();
    } else {
      easy.username(&cloud_user).unwrap();
      easy.password(&cloud_password).unwrap();
    }
    easy.http_headers(list).unwrap();
    easy.perform().unwrap();
    let contents = easy.get_ref();
    let contents_string = String::from_utf8_lossy(&contents.0);
    let mut reader = Reader::from_str(&contents_string);
    reader.trim_text(true);
    let mut txt = Vec::new();
    let mut buf = Vec::new();
    loop {
      match reader.read_event(&mut buf) {
        Ok(Event::Text(e)) => txt.push(e.unescape_and_decode(&reader).unwrap()),
        Ok(Event::Eof) => break,
        Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
        _ => (),
      }
      buf.clear();
    }
    if count == 0 {
      if txt[0] == "Sabre\\DAV\\Exception\\NotFound" {
        if !cloud_is_source && local_is_dir == false {
          files.insert("NotFound".to_string(), 1);
        }
        return (dirs, files);
      }
      txt.remove(0);
    } else {
      txt.remove(0);
    }
    if txt[0].parse::<u64>().is_ok() {
      files.insert(cloud_path.to_string(), txt[0].parse::<u64>().unwrap());
      return (dirs, files);
    }
    if cloud_is_source == false && local_is_dir == false {
      return (dirs, files);
    }
    let mut file = String::new();
    for element in txt {
      if element.ends_with("/") {
        let mut dir = element.to_string().split_off(cloud_prefix_count);
        dir.pop();
        let mut dir_string = percent_decode(&dir.into_bytes()).decode_utf8().unwrap().to_string();
        dir_string = format!("{}/", dir_string);
        dirs.push(dir_string);
        dir_queue.push(element.to_string());
      } else if element.starts_with("/") && !element.ends_with("/") {
        let mut file_element = element.clone();
        file = file_element.split_off(cloud_prefix_count);
      } else if file != "" {
        let size = element.parse::<u64>().unwrap();
        files.insert(file.to_string(), size);
        file = "".to_string();
      }
    }
    count += 1;
  }
  return (dirs, files);
}

fn cloud_exec_url(cloud_path: &str, cloud_url: &str, cloud_user: &str, mode: &str) -> String {
  let mut url = String::with_capacity(300);
  if mode == "auth" || mode == "authcheck" {
    url.push_str(&cloud_url);
    url.push_str("/ocs/v1.php/cloud/users/");
    url.push_str(&cloud_user);
  } else {
    url.push_str(&cloud_url);
    url.push_str("/remote.php/dav/files/");
    url.push_str(&cloud_user);
    url.push_str("/");
    url.push_str(&cloud_path);
  }
  return url;
}

fn cloud_exec_url_count(cloud_path: &str, cloud_user: &str) -> usize {
  let mut url = String::with_capacity(300);
  url.push_str("/remote.php/dav/files/");
  url.push_str(&cloud_user);
  url.push_str("/");
  url.push_str(&cloud_path);
  url.push_str("/");
  url.shrink_to_fit();
  let count = url.capacity();
  return count;
}

