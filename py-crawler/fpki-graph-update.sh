#------------------------------------------------------
# Setup important variables
#------------------------------------------------------
# SCRIPT DIRECTORY
SCRIPT_DIRECTORY=$(pwd)
# Today's date, for git submissions
TODAY=$(date +%m%d)
# Secret file location
SECRET_FILE="$SCRIPT_DIRECTORY/py_crawler/secrets/accesstoken"

#------------------------------------------------------
# Confirm env variable (if run from doocker) is present
#------------------------------------------------------
# Directory where we will install the Playbooks site from github
if test -v $PLAYBOOKS_DIR; then
  echo "Playbooks Directory set by docker to $PLAYBOOKS_DIR"
else
  echo "No \$PLAYBOOKS_DIR set. Setting to ../PLAYBOOKS_REPO"
  PLAYBOOKS_DIR="../PLAYBOOKS_REPO"
fi

# Directory where we will keep the output of the command
if test -v $OUTPUT_DIR; then
  echo "Playbooks Directory set by docker to $OUTPUT_DIR"
else
  echo "No \$OUTPUT_DIR set. Setting to ../OUTPUT"
  OUTPUT_DIR="../OUTPUT"
fi


#------------------------------------------------------
# Confirm secret is present
#------------------------------------------------------
if test -f "$SECRET_FILE"; then
  # Set Access Token
  GH_TOKEN=$(cat "$SECRET_FILE")
else
  echo No secret file present at
fi

#------------------------------------------------------
# Set up GIT Variables
#------------------------------------------------------
# GIT REPO URL
PLAYBOOKS_REPO="Credentive-Sec/ficam-playbooks"
# GIT USERNAME
GH_USERNAME="RS-Credentive"
# REPO URL
PLAYBOOKS_REPO_URL="https://$GH_TOKEN@github.com/$PLAYBOOKS_REPO"

#------------------------------------------------------
# Run py_crawler
#------------------------------------------------------
poetry run python -m py_crawler

#------------------------------------------------------
# Update Playbooks site with new artifacts
#------------------------------------------------------
if ! test -d $PLAYBOOKS_DIR; then
    # If the playbooks site doesn't exist here, create it
    mkdir $PLAYBOOKS_DIR
fi

(
    cd "$PLAYBOOKS_DIR" || exit
    # initialize and update the repo
    echo "Initializing the playbooks REPO"
    git init
    git config --global user.email "fpki-graph-update@credentive.com"
    git config --global user.name "FPKI Graph Updates"
    git remote add origin "$PLAYBOOKS_REPO_URL"
    git pull origin staging
    # Create a branch for this run
    echo "Creating a branch for the current Run"
    git checkout -B "$TODAY-fpki-graph-update"

    # Update the site with the new artifacts
    echo "Updating site with new artifacts"
    cp "$OUTPUT_DIR/CACertificatesValidatingToFederalCommonPolicyG2.p7b" _fpki/tools/
    cp "$OUTPUT_DIR/fpki-certs.gexf" _fpki/tools/
    sed -e "s/\*\*Last Update\*\*: .*/\*\*Last Update\*\*: $(date +"%B %d, %Y")/" _fpki/tools/fpki_tools_graph.md > _fpki/tools/fpki_tools_graph.tmp
    mv _fpki/tools/fpki_tools_graph.tmp _fpki/tools/fpki_tools_graph.md

    # Submit the playbooks updates to the git repo
    echo "Submitting updates to origin"
    git add -A
    git commit -m "automatic crawler update"
    git push --all

     # Authenticating GH with a token
     echo "Authenticating GH CLI"
     gh auth login --with-token $GH_TOKEN

     # Create Issue, record the output to a variable
     echo "Creating Issue"
     ISSUE=$(gh issue create --repo "$PLAYBOOKS_REPO" --title "$TODAY FPKI Graph Update"  --body "Automatically Created")

     # Parse out the issue number
     ISSUE_NUM=$(echo $ISSUE | cut -f 7 -d "/")

     # Open a PR linked to the Issue
     echo "Creating PR"
     gh pr create --repo "$PLAYBOOKS_REPO" --base "staging" --title "$TODAY Fpki Graph Update" --body "Linked to Issue #$ISSUE_NUM"
)