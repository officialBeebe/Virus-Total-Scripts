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