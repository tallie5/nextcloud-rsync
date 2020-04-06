# nextcloud-rsync  
Sync utility allowing directory to directory, recursive transfers using Nextcloud's WebDAV interface.  
**This is a personal project and not ready for use by anyone.**  

## Usage  
### Environment Variables  
#### Required:  
NEXTCLOUD_URL  
* example: `export NEXTCLOUD_URL=https://nextcloud.mydomain.com`  

NEXTCLOUD_USER  
* example: `export NEXTCLOUD_USER=testuser`  

#### Optional:  
NEXTCLOUD_PASSWORD  
* User will be prompted for password if not supplied.  

NEXTCLOUD_COOKIE  
* Location of cookie file ([NEXTCLOUD_COOKIE]/.config/nextcloud-rsync)  
* If not specified, cookie file will be created in $HOME/.config/nextcloud-rsync  

#### Operation and Syntax:
~~ denotes a directory in Nextcloud  
If the root directory does not exist in the destination, nextcloud-rsync will create the structure.  
Because Nextcloud does not provide hashes of files, differences between files are calculated by file size. This means that some files may not be updated if they contain the exact amount of bytes as their previous versions.  

`nextcloud-rsync local-directory ~~/remote-directory`  
* Transfers all files from local-directory to remote-directory, updating modified files  

`nextcloud-rsync ~~/remote-directory local-directory`  
* Transfers all files from remote-directory to local-directory, updating modified files  

`nextcloud-rsync --delete local-directory ~~/remote-directory`  
* Transfers all files from local-directory to remote-directory, updating modified files and deleteing all files that are not in the source  

### Arguments
-d or --delete | Also removes files from destination that are not in source.  
-l or --ignore-links | Ignore symlinks. By default, symlinks are followed.  
-v or --verbose | Prints vectors of directores and files for debugging the app itself.  
-V or --version | Prints version of app.  
-p or --parallel= | Specifies thread count. By default, thread count will equal CPU thread count.  
* example: `--parallel=4` or example: `-p 4`  
