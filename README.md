## clean-filters
This script will list out of delete the saved searches/filters within Tenable.IO for a specific account or a list of user accounts. 

This was created out of a strange issue in which a saved search was shared out and the user(s) would have an empty set and the ability to delete would be removed the corrupted saved search.

```
usage: clean-filters.py [-h] [-target TARGET] [-targetlist TARGETLIST] [-sharedby SHAREDBY] [-whatif]

Delete Vulnerability filters for a user account

optional arguments:
   -h, --help            show this help message and exit
   -target TARGET        Username to target
   -targetlist TARGETLIST
                         Path to text file containing list of usernames
   -sharedby SHAREDBY    Filter saved searches 'shared by' username
   -whatif               Run but do not delete

Examples:
    Delete filters that are shared by admin@domain.com with the user@domain.com account 
    ./clean-filters.py -target user@domain.com -sharedby admin@domain.com

    List filters that would be deleted for user@domain.com
    ./clean-filters.py -target user@domain.com -whatif
```
