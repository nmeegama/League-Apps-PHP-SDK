# Sample PHP code to access League apps secure admin API

A example of PHP code to access the  League apps secure admin API. 
- Documentation for the API : http://leagueapps.com/wp-content/uploads/2017/11/LeagueApps-Connect-API-Overview.pdf

## Installation

- Run the following command to install dependencies. 

```shell
composer intall 
```
- Include the key.p12 and change the constant in index.php file
``` php
define("KEY_FILE_PATH", "<your file path>");
```
thats it.

### Dependencies

- PHP 7.1 > 
- OpenSSL Extension
 