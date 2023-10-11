# Before your First Run of Docker

Before your first run of Docker, to make sure running of the this Dockerfile functions correctly do the following:

1. Log into your GitHub account, create an `accesstoken`.
2. Then paste it into the following file: `py-crawler/py-crawler/secrets/accesstoken` in this directory.
3. Next: add your GSA approved GitHub Username and Email Address to: `py-crawler/fpki-graph-update.sh` near the top

```bash
GH_USERNAME=""
GH_EMAILADDRESS=""
```


## DEVMODE 

**File:** `py-crawler/fpki-graph-update.sh`

If you are testing on your own repo clone of Idmanagement.gov, please be sure to change `DEVMODE` to equal true, then change it back to false when done testing.

```bash
DEVMODE=true
```

and also, set the `DEVREPO` to the address of your cloned repo of `idmanagement.gov`

Example: 
```bash
DEVREPO="claytonjbarnette/idmanagement.gov" 
```


## PRODMODE 

**File:** `py-crawler/fpki-graph-update.sh`

Once you have entered all of your information in the `fpki-graph-update.sh` file, and `DEVMODE` is set to `false`, this script will run in production mode against idmanagement.gov staging.

```bash
DEVMODE=false
```

After this point, the instructions for running the `py-crawler` will apply, except where it speaks of *accesstokens*, *GitHub credintials* which has already been provided. For more information: see: [README.md](README.md).

