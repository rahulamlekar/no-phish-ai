import os
os.environ['LANGCHAIN_TRACING_V2'] = 'true'
os.environ['LANGCHAIN_ENDPOINT'] = 'https://api.smith.langchain.com'
os.environ['LANGCHAIN_API_KEY'] = 'redacted'
os.environ['LANGCHAIN_PROJECT'] = 'no-phish-ai'
os.environ['OPENAI_API_KEY'] = 'sk-redacted'


from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI()
llm.invoke("Hello, world!")