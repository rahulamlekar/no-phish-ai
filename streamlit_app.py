import streamlit as st

import asyncio
import json
import os
import socket
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import OpenSSL
import requests
import tldextract
import tiktoken
import whois
from dotenv import load_dotenv, find_dotenv
from pyppeteer import launch
from pyppeteer.errors import TimeoutError
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage
from langsmith.run_helpers import traceable

os.environ['LANGCHAIN_TRACING_V2'] = 'true'
os.environ['LANGCHAIN_ENDPOINT'] = 'https://api.smith.langchain.com'
os.environ['LANGCHAIN_API_KEY'] = 'LANGCHAIN_API_KEY'
os.environ['LANGCHAIN_PROJECT'] = 'no-phish-ai'
os.environ['OPENAI_API_KEY'] = 'OPENAI_API_KEY'

# Constants
ENCODING_TYPE = "cl100k_base"
LLM_MODEL = "gpt-4-0613"
TEMPERATURE = 0

# Load environment variables
load_dotenv(find_dotenv())

# Initialize global objects
encoding = tiktoken.get_encoding(ENCODING_TYPE)
llm = ChatOpenAI(model=LLM_MODEL, temperature=TEMPERATURE)


async def extract_elements(url):
    browser = None
    try:
        browser = await launch()
        page = await browser.newPage()
        try:
            await page.goto(url)
        except TimeoutError:
            print(f"Timeout while navigating to {url}. Skipping...")
            await browser.close()
            return None
        except Exception as e:
            print(f"An error occurred while navigating to {url}: {e}")
            await browser.close()
            return None

        await asyncio.sleep(5)

        page_text = await page.evaluate('document.body.innerText')
        
        forms_and_actions = await page.evaluate('''() => {
            return Array.from(document.querySelectorAll("form")).map(form => {
                return {
                    'formHTML': form.outerHTML,
                    'actionURL': form.action
                };
            });
        }''')

        links = await page.evaluate('''() => {
            return Array.from(document.querySelectorAll("a")).map(link => link.href);
        }''')

        scripts = await page.evaluate('''() => {
            return Array.from(document.querySelectorAll("script")).map(script => script.outerHTML);
        }''')

        meta_info = await page.evaluate('''() => {
            return Array.from(document.querySelectorAll("meta")).map(meta => meta.getAttribute("name") + "=" + meta.getAttribute("content"));
        }''')

        title = await page.evaluate('''() => {
            return document.title;
        }''')

        await browser.close()

        extracted_data = {
            'title': title,
            'text_content': page_text,
            'forms_and_actions': forms_and_actions,
            'links': links,
            'meta_info': meta_info,
            'scripts': scripts,
        }

        return extracted_data

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if browser:
            await browser.close()
        return None

@traceable(run_type="tool")
def fetch_dns_records(domain):
    record_data = {}
    
    # Fetch A records
    try:
        answers = dns.resolver.resolve(domain, 'A')
        record_data['A'] = [answer.address for answer in answers]
    except Exception as e:
        print(f"An error occurred fetching A records: {e}")
        
    # Fetch CNAME records
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        record_data['CNAME'] = [answer.target.to_text() for answer in answers]
    except Exception as e:
        print(f"An error occurred fetching CNAME records: {e}")

    return record_data

@traceable(run_type="tool")
def fetch_tls_certificate(host, port=443):
    cert_details = {}
    
    try:
        # Create a socket and wrap it with SSL
        conn = socket.create_connection((host, port))
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        sock = OpenSSL.SSL.Connection(context, conn)
        
        # Connect and fetch certificate
        sock.set_connect_state()
        sock.set_tlsext_host_name(host.encode())
        sock.do_handshake()
        cert = sock.get_peer_certificate()
        
        # Extract certificate details
        cert_details['issuer'] = cert.get_issuer().get_components()
        cert_details['subject'] = cert.get_subject().get_components()
        cert_details['expiration_date'] = cert.get_notAfter().decode('ascii')
        
        # Close the connection
        conn.close()
        
        return cert_details, None

    except socket.gaierror:
        return None, "Could not resolve host"
    except socket.timeout:
        return None, "Connection timed out"
    except OpenSSL.SSL.Error as e:
        return None, f"SSL error: {e}"
    except Exception as e:
        return None, f"An unexpected error occurred: {e}"
    
def truncate_to_max_tokens(text, encoding, max_tokens=7500):
    token_integers = encoding.encode(text)
    if len(token_integers) > max_tokens:
        truncated_tokens = token_integers[:max_tokens]
        truncated_text = encoding.decode(truncated_tokens)
        return truncated_text
    else:
        return text

@traceable(run_type="llm")
def phishing_insights_extractor_tool(report):
    
    # Get the token count
    token_integers = encoding.encode(report)
    num_tokens = len(token_integers)
    print("Token count for input:", num_tokens)
    
    # Truncate if needed
    if num_tokens > 7500:
        report = truncate_to_max_tokens(report, encoding, max_tokens=7500)
        
    first_response = llm.predict_messages([HumanMessage(content=report)],
                                          functions=phishing_page_insights_schema)

    content = first_response.content
    function_call = first_response.additional_kwargs.get('function_call')

    if function_call is not None:
        content = function_call.get('arguments', content)

    try:
        content_dict = json.loads(content)
        print("Content dict: ", content_dict)
        return content_dict
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON content: {content}")
        print(f"Content that caused the error: {report}")
        return None

@traceable(run_type="tool")
def analyze_whois(domain):
    analysis = {}
    try:
        w = whois.whois(domain)
        
        # Analyzing Registration Date
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            age = (datetime.now() - creation_date).days
            analysis['Domain_Age_In_Days'] = age

        # Analyzing Registrar
        if w.registrar:
            analysis['Domain_Registrar'] = w.registrar
        
        # Analyzing Country
        if w.country:
            analysis['Domain_Registered_Country'] = w.country

    except Exception as e:
        analysis['Error_Message'] = str(e)
        
    return analysis

phishing_page_insights_schema = [
            {
                "name": "phishing_page_insights_extractor",
                "description": "Extract and determine if a webpage is a potential phishing page",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "phishing_reason": {
                            "type": "string",
                            "description": "What is the determined reason for the phishing page or 'Unknown' if it is not clear",
                        },
                        "safe_reason": {
                            "type": "string",
                            "description": "What is the determined reasos why this is not a phishing page or 'Unknown' if it is not clear",
                        },
                        "likelihood": {
                            "type": "string",
                            "description": "What is the likelihood this is a phishing page",
                            "enum": ["High", "Medium", "Low", "Unknown"]
                        },
                         "threat_score": {
                            "type": "integer",
                            "description": "What is the determined security score for the phishing page on a scale of 10 to 100. 100 being not safe and 10 being not secure",
                            "enum": ["10", "20","30","40","50","60","70","80","90","100"]
                        },
                         "security_summary": {
                            "type": "string",
                            "description": "What is the determined security summary for the phishing page or 'Unknown' if it is not clear",
                        },
                        "likelihood_reason": {
                            "type": "string",
                            "description": "The explanation for why the likelihood was  or 'Unknown' if it is not clear"
                        },
                        "malicious_url": {
                            "type": "string",
                            "description": "The url of the malicious page or 'Unknown' if it is not clear"
                        },
                    },
                    "required": ["phishing_reason", "safe_reason", "likelihood", "likelihood_reason","security_score","security_summary"],
                }
            }
        ]

@traceable(run_type="chain")
async def analyze_url(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    host = f"{extracted.subdomain}.{domain}" if extracted.subdomain else domain
    rendered_content = await extract_elements(url)

    dns_record = fetch_dns_records(domain)
    tls_record = fetch_tls_certificate(host)
    who_is_records = analyze_whois(domain)

    # Construct the input string
    constructed_input = f"{url} {dns_record} {tls_record} {who_is_records} {rendered_content}"
    return phishing_insights_extractor_tool(constructed_input)

def main():
    st.title('No Phish AI')
    url = st.text_input('Enter the URL to analyze:', '')
    if st.button('Analyze'):
        if url:
            results = asyncio.run(analyze_url(url))
            if results:
                st.write("Analysis Results:")
                st.json(results)
            else:
                st.error("Failed to analyze the URL.")
        else:
            st.warning("Please enter a valid URL.")

if __name__ == "__main__":
    main()
