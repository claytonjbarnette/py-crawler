# Using Py-Crawler

This tool is a replacement for the legacy FPKI Crawler, that has the following advantages over its predecessor:
1. It is a much simpler design and implementation, and thus much easier to customize for new requirements.
2. It is designed specifically to operate in a cloud/container environment, offering flexibility of operation
3. It support multiple output formats, not just GEXF, and additional output formats can be easily added.
4. It produced much more usable and readable outputs, designed to clearly identify errors in processing or other issues that prevent the full PKI Graph from being built.
5. It automates previously manual processes such as opening pull requests and issues.

## Installing Py-Crawler
Py-crawler may run independently, but it is designed to operate in the context of containerized workflow. Docker (including docker-compose) are required for the successful execution of py-crawler.

The Py-crawler code is available from github. The repository is self contained, and has all of the elements required for execution except for the github authentication token which must be provided by the user.

To obtain a github authentication token, follow the instructions at <INSERT URL>

Once the token has been issued, copy the contents of the token to a file called "accesstoken" under the dierctory "py-crawler/py_crawler/secrets"

## Running Py-Crawler
Once the prerequisites have been met, py-crawler can be executed by running "docker-compose up" from the main repo directory. If necessary it will build the docker container and install all necessary tools before executing the tool.

The tool itself will grab the latest copy of the playbooks repo, create the new files necessary for the graph updates in a new branch, push the new branch to github and open the required issues and pull requests. All that should be required is to verify the output, and identify any followup actions.

## Interpreting the output
Py-crawler produces two output files during ordinary operation:
1. A json file containing the important results of the crawler run, and
2. a debug log file with detailed information about the execution of the process.

For any change in the graph between runs, the json file should be the first stop. This file contains the following elements:

