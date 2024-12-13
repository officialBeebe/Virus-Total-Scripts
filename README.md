# Overview

Pure functional CLI script that uses the Virus Total API to scan URLs and files for malware.

This script can also be containerized with Docker for easier deployment. See the instructions below for more details.

> You will need an API key from Virus Total to use this script. You can get one by signing up for a free
> account [here](https://www.virustotal.com/gui/join-us).

# Instructions

## Clone repo

```bash
git clone https://github.com/officialBeebe/Virus-Total-Scripts.git
cd Virus-Total-Scripts
```

## Create a virtual environment

If you haven't already setup your python environment, you can do so by following the steps in the links below

- [Install python3](https://docs.python-guide.org/starting/installation/)
- [Install Pipenv and Virtualenv](https://docs.python-guide.org/dev/virtualenvs/#virtualenvironments-ref)

After you've installed the necessary tools, you can create a virtual environment by running the following command in the
root directory of the project

> Virtual environments allow you to install dependencies for a specific project without affecting other projects on your
> system. This is useful when you have multiple projects that require different versions of the same package.

```bash
virtualenv venv
```

## Activate the virtual environment

Activation of the virtual environment is different depending on the operating system you are using.

```bash
source venv/bin/activate # Linux or MacOS
venv\Scripts\activate # Windows
```

## Install requirements

Once you've activated the virtual environment you can install packages normally using pip.

Once you're ready to distribute your project, you can run the following command to generate a requirements.txt file.
This can be used to replicate the same environment on another machine.

```bash
pip freeze > requirements.txt # Save dependencies to a file
pip install -r requirements.txt # Install dependencies from a file
```

## Configure the API key

You will need to create a '.env' file in the project root and add your API key to it.

```plaintext
API_KEY=your_api_key_here
```

If you installed the requirements properly from the last step, python-dotenv will take care of the rest.

## Run the script

Yea so now that you've activated your virtual environment and installed the necessary dependencies, you can run the
script like normal.

If you didn't include an API_KEY entry in '.env' you can include the '-k' flag follwed by your key.

Example:

```bash
python src/main.py -k your-api-key -u http://www.virustotal.com # Scan a URL and output a report
```

For help with the script, you can run the following command

```bash
python src/main.py -h
```

Alternatively, you can build the docker image and run the script from there.

```bash
docker build -t my-vt .
docker run --rm -e API_KEY="your-api-key" my-vt -u http://www.virustotal.com # -k applies normally here as mentioned above
````

Additionally, if you did add API_KEY=your-api-key entry
 to the '.env' file you can rebuild the docker image and run the following command:

```bash
docker run my-vt -u http://www.virustotal.com
```

How lovely is that?

## Deactivate the virtual environment

You can either close the terminal like a savage or you can deactivate the virtual environment like a civilized person.

```bash
deactivate
```

# Notes

Currently the tool includes options for the most popular Virus Total operations for scanning:

- URLs
- File uploads
- Domains
- IP addresses

Malware analysis is performed by third-party engines supported by Virus Total. The tool doesn't provide any sort of analysis by itself.

Please note that this script is for educational purposes only. I am not responsible for any misuse of this script.