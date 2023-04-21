#------------------------------------------------------
# Verify Environment
#------------------------------------------------------
if ! test -f /py-crawler/py_crawler/secrets/accesstoken; then
    # The secrets file does not exist. Bail
    echo "No Secrets file detected. See the project README.md for instructions"
    exit
fi




#------------------------------------------------------
# Setup important variables
#------------------------------------------------------
# Todays date, for git submissions
TODAY=`date +%m%d`
# Directory where we will install the Playbooks site from github
PLAYBOOKS_DIRECTORY="/PLAYBOOKS_SITE"
# Git Project Name
PLAYBOOKS_PROJECT="ficam-playbooks"
# GIT REPO URL 
PLAYBOOKS_REPO="Credentive-Sec/ficam-playbooks"
# GIT USERNAME
GIT_USERNAME="RS-Credentive"
# Access Token
GIT_TOKEN=`cat /py-crawler/py_crawler/secrets/accesstoken`
# REPO URL
PLAYBOOKS_REPO_URL="https://$GIT_USERNAME:$GIT_TOKEN@github.com/$PLAYBOOKS_REPO"
# SCRIPT DIRECTORY
SCRIPT_DIRECTORY="/py-crawler"

#------------------------------------------------------
# Run py_crawlker
#------------------------------------------------------
python -m py_crawler

#------------------------------------------------------
# Update Playbooks site with new artifacts
#------------------------------------------------------
if ! test -d $PLAYBOOKS_DIRECTORY; then
    # If the playbooks site doesn't exist here, create it
    mkdir $PLAYBOOKS_DIRECTORY
fi

(
    cd $PLAYBOOKS_DIRECTORY
    # initialize and update the repo
    echo "Initializing the playbooks REPO"
    git init
    git config --global user.email "fpki-graph-update@credentive.com"
    git config --global user.name "FPKI Graph Updates"
    git remote add origin $PLAYBOOKS_REPO_URL
    git pull origin staging
    # Create a branch for this run
    echo "Creating a branch for the current Run"
    #git branch $TODAY-fpki-graph-update
    git checkout -B $TODAY-fpki-graph-update

    # Update the site with the new artifacts
    echo "Updating site with new artifacts"
    cp $SCRIPT_DIRECTORY/CACertificatesValidatingToFederalCommonPolicyG2.p7b _fpki/tools/
    cp $SCRIPT_DIRECTORY/fpki-certs.gexf _fpki/tools/
    sed -e "s/\*\*Last Update\*\*: .*/\*\*Last Update\*\*: `date +"%B %d, %Y"`/" _fpki/tools/fpki_tools_graph.md > _fpki/tools/fpki_tools_graph.tmp
    mv _fpki/tools/fpki_tools_graph.tmp _fpki/tools/fpki_tools_graph.md

    # Submit the playbooks updates to the git repo
    echo "Submitting updates to origin"
    git add -A
    git commit -m "automatic crawler update"
    git push --all

    # Authenticating GH with a token
    echo "Authenticating GH CLI"
    gh auth login --with-token < /github_token

    # Create Issue, record the output to a variable
    echo "Creating Issue"
    ISSUE=$(gh issue create --repo "$PLAYBOOKS_REPO" --title "$TODAY FPKI Graph Update"  --body "Automatically Created")

    # Parse out the issue number
    ISSUE_NUM=$(echo $ISSUE | cut -f 7 -d "/")

    # Open a PR linked to the Issue
    echo "Creating PR"
    gh pr create --repo "$PLAYBOOKS_REPO" --base "staging" --title "$TODAY Fpki Graph Update" --body "Linked to Issue #$issue_num"
)