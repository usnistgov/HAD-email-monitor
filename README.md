#dns-monitor - An Email Monitor Written in Go

##Data Structure
The tool runs a series of tests using a list of zones as input.  The results are stored in structures, which are then converted to BSON
objects and stored in a MongoDB database.  The database is expected to have a DB called "email", in which the tool will store all the 
documents in a collection **dns.name**

* Zone name (string)
* Agency name (org name) (string)
* Time checked (as 64bit int)
* SPF policy (string)
* DKIM key (string)
* DKIM Selector (string)
* DMARC policy (string)
* DANE usage (boolean)
* MTA-STS RR (string)
* MTA-STS policy (list of strings)
* MX List (list of strings)
* STARTTLS (boolean)
* Certificate (string) *Not fully implemented yet*


##To run the dns-monitor:

`email-monitor -config=<configuration filename>`

where:

* config: the configuration file name.  See monitor.conf for an example.


##Input:
The input for the dns-monitor is a CSV file.  Each input line has the format:

Zone,Agency,Location

Only the first two values are used.  The original version of the file was gotten from [data.gov][https://home.dotgov.gov/data/]