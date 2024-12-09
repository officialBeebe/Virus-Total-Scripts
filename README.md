# Overview

Pure functional CLI script that uses the Virus Total API to scan URLs and files for malware.

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

Example:

```bash
python src/main.py -u http://www.virustotal.com --print # Scan a URL and print the results
```

For help with the script, you can run the following command

```bash
python src/main.py -h
```

## Deactivate the virtual environment

You can either close the terminal like a savage or you can deactivate the virtual environment like a civilized person.

```bash
deactivate
```

# Notes

This script has a lot ahead of it. I plan on implementing more features and containerizing the script for easier
deployment. I'm not taking any feature requests at the moment but if you have any suggestions, feel free to open an
issue.

Please note that this script is for educational purposes only. I am not responsible for any misuse of this script.