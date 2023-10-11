
#------------------------------------------------------
# PRERUN SETTINGS: Important! 
# Please set your GitHub Username and Email address below before running Docker.
# Note: Also make sure you added you accesstoken form GitHub to the /py_crawler/secrets/accesstoken
# and change DEVMODE if testing on your own repo and branches
#------------------------------------------------------
GH_USERNAME=""
GH_EMAILADDRESS=""

# Bail if the above is not set. 
if [$GH_USERNAME="" || $GH_EMAILADDRESS=""]; then
  echo "Your GSA Username or Email Address is blank\n"
  echo "Please update this file and retry."
  exit;
fi


#------------------------------------------------------
# Development vs Production
#
# Set DEVMODE to true to test on your own [exp: clatonjbarnette/idmanagement.gov] repo
# else: this script runs in production mode for idmanagement.gov
#------------------------------------------------------
DEVMODE=false
DEVREPO="claytonjbarnette/idmanagement.gov" # specify your own repo here for testing.
PRODREPO="GSA/idmanagement.gov" # default repo

if [DEVMODE=true]; then
# REPO is development repo specified by user
  REPO=$DEVREPO
  echo "DEVMODE: Setting DEVELOPMENT REPO to $REPO"
else
# REPO is production staging repo: gsa/idmanagement.gov
  REPO=$PRODREPO
  echo "PRODMODE: Setting PRODUCTION REPO to $REPO"  
fi

#------------------------------------------------------
# Setup important variables
#------------------------------------------------------
# SCRIPT DIRECTORY
SCRIPT_DIRECTORY=$(pwd)
# Secret file location
SECRET_FILE="$SCRIPT_DIRECTORY/py_crawler/secrets/accesstoken"

#------------------------------------------------------
# Confirm env variable (if run from doocker) is present
#------------------------------------------------------
# Directory where we will install the idmanagement.gov site from github
if [ -v REPO_DIR ]; then
  echo "Git Repo Directory set by docker to $REPO_DIR"
else
  echo "No \$REPO_DIR set. Setting to ../REPO"
  REPO_DIR="../REPO"
fi

# Directory where we will keep the output of the command
if [ -v OUTPUT_DIR ]; then
  echo "Output Directory set by docker to $OUTPUT_DIR"
else
  echo "No \$OUTPUT_DIR set. Setting to ../OUTPUT"
  OUTPUT_DIR="../OUTPUT"
fi


#------------------------------------------------------
# Run py_crawler
#------------------------------------------------------
poetry run python -m py_crawler

#------------------------------------------------------
# Update IDManagement.gov site with new artifacts
#------------------------------------------------------

#------------------------------------------------------
# Confirm secret is present
#------------------------------------------------------
if test -f "$SECRET_FILE"; then
  # Set Access Token
  GH_TOKEN=$(cat "$SECRET_FILE")
else
  echo No secret file present at $SECRET_FILE
fi

#------------------------------------------------------
# Set up GIT Variables
#------------------------------------------------------
# GIT REPO URL
 # Updaed: see Development check above CB
# BRANCH FOR THIS RUN
BRANCH=$(date +%m%d)-fpki-graph-update

if ! test -d $REPO_DIR; then
    # If the idmanagement.gov site doesn't exist here, create it
    echo "Setting \$REPO_DIR to $REPO_DIR"
    mkdir $REPO_DIR
fi

(
  echo "Executing gh auth login"
  echo $GH_TOKEN | gh auth login --with-token
  gh auth setup-git
  cd "$REPO_DIR" || { echo "IDManagement directory does not exist!"; exit; }

  # See if we've already initialized the git repo here
  if [ "$(git rev-parse --is-inside-work-tree)" = "true" ]; then
    # switch to staging branch
    echo "Switching to 'staging' branch"
    git branch staging
    # sync the repo
    echo "Repo found. Syncing..."
    gh repo sync --force
    echo "Deleting branches that have been merged"
    git branch --merged | xargs git branch -d
  else
    # initialize and update the repo
    echo "Initializing the IDManagement REPO"
    gh repo clone $REPO .
    gh repo set-default $REPO
    git config user.name "$GH_USERNAME"
    git config user.email $GH_EMAILADDRESS
  fi

  echo "Checking for local branch for the current run"
  if [ "$(git branch --list $BRANCH)" = "" ]; then
    # Create a branch for this run
    echo "Creating a branch for the current Run"
    git checkout -B "$BRANCH"
  else
    echo "Branch exists. Switching..."
    git switch $BRANCH
  fi

  # Update the site with the new artifacts
  echo "Updating site with new artifacts"
  cp "$OUTPUT_DIR/CACertificatesValidatingToFederalCommonPolicyG2.p7b" _implement/tools
  cp "$OUTPUT_DIR/fpki-certs.gexf" _implement/tools
  cp "$OUTPUT_DIR/crawler-lastrun.json" _implement/tools
  sed -e "s/\*\*Last Update\*\*: .*/\*\*Last Update\*\*: $(date +"%B %d, %Y")/" _implement/fpki_notifications.md > _implement/fpki_notifications.md.tmp
  mv _implement/fpki_notifications.md.tmp _implement/fpki_notifications.md

  # Check for open PR
  # OPEN_PR=$(gh pr list --head $(date +%m%d)-fpki-graph-update --json number)

  # Submit the idmanagement updates to the git repo
  echo "Adding and commiting updates"
  git add -A
  git commit -m "automatic crawler update"
  echo "Submitting updates to origin"
  git push --all

  # Create Issue, record the output to a variable
  echo "Creating Issue"
  ISSUE=$(gh issue create --repo "$REPO" --title "$(date +%m%d) FPKI Graph Update"  --body "Automatically Created")

  # Parse out the issue number
  ISSUE_NUM=$(echo $ISSUE | cut -f 7 -d "/")

  # Open a PR linked to the Issue
  # echo "Creating PR"
  # gh pr create --repo "$REPO" --head "$BRANCH" --base "staging" --title "$(date +%m%d) Fpki Graph Update" --body "Closes #$ISSUE_NUM"
)