# Week 4: CTF - web

## Goal
> Get access as an administrator in a wordpress server using a known CVE exploit.

### Challenge 1
> First of all we explored the website to collect some information regarding the wordpress version, the used plugins and the platform users.  

> On the [WordPress Hosting service page](http://ctf-fsi.fe.up.pt:5001/product/wordpress-hosting/), in the additional information section, it's possible to check the wordpress and the used plugins versions: 
> * Wordpress - 5.8.1
> * WooCommerce plugin - 5.7.1
> * Booster for WooCommerce plugin - 5.4.3

> With this information we searched in a [CVE](https://cve.mitre.org/index.html) database for the correct CVE. After some tries, we tried the keywords 'wordpress' and 'Woocomerce Booster' which gave us 11 results. The [CVE-2021-34646](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34646) description matched the specifications that we were looking for.  
> The correct flag for challenge 1 was found: *flag{CVE-2021-34646}*


### Challenge 2

> On challenge two we started by searching in the Exploit Database platform for a exploit regarding the CVE-2021-34646.  
> We came across an exploit called [
WordPress Plugin WooCommerce Booster Plugin 5.4.3 - Authentication Bypass
](https://www.exploit-db.com/exploits/50299) that's specifically created to run against the CVE.

> First we used the URL -  http://ctf-fsi.fe.up.pt:5001/wp-json/wp/v2/users - to access the list of users and their id's.  
> With the id of the administrator we now could download the given python file and execute it with the correct parameters:
> * *./exploit_CVE-2021-34646.py [URL] [Admin id]*
> * *./exploit_CVE-2021-34646.py http://ctf-fsi.fe.up.pt:5001/ 1*

> After executing the file three links were generated and one of them allowed us to access the system as the administrator.
> Then we just followed the [link](http://ctf-fsi.fe.up.pt:5001/wp-admin/edit.php) provided in moodle, accessed a private post for the employess and found the flag!  
> The correct flat for challenge 2 was: *flag{please don't bother me}*

