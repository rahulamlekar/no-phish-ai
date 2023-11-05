import os
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain.schema import SystemMessage
os.environ['LANGCHAIN_TRACING_V2'] = 'true'
os.environ['LANGCHAIN_ENDPOINT'] = 'https://api.smith.langchain.com'
os.environ['LANGCHAIN_API_KEY'] = 'ls__85291a99f2ab490bab7da20a3f9b254e'
os.environ['LANGCHAIN_PROJECT'] = 'no-phish-ai'
os.environ['OPENAI_API_KEY'] = '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'

chat_template = ChatPromptTemplate.from_messages(
    [
        SystemMessage(
            content=(
                "You are a security assistant that tells users about phishy sites."
            )
        ),
        HumanMessagePromptTemplate.from_template("{text}"),
    ]
)

llm = ChatOpenAI()
llm(chat_template.format_messages(text="google.com"))