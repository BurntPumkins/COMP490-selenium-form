import requests
from bs4 import BeautifulSoup
import re

def extract_function_from_gist(gist_url):
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    response = requests.get(gist_url, headers=headers)
    if response.status_code != 200:
        print("invalid link")
        return None

    soup = BeautifulSoup(response.text, "html.parser")
    article = soup.find("article", class_="markdown-body entry-content container-lg")
    if not article:
        print("no article found")
        return None

    p_tags = article.find_all("p", attrs={"dir":"auto"})
    if len(p_tags) < 5:
        print("unable to find 5th p tag")
        return None

    target_p = p_tags[4]
    code_tags = target_p.find_all("code")
    if len(code_tags) < 2:
        print("unable to find 2th code tag")
        return None

    function_name = code_tags[1].text.strip()

    return function_name


if __name__ == "__main__":
    sign = True
    while(sign):
        gist_link = input("Input gist link that you want to extract: ").strip()
        print(extract_function_from_gist(gist_link))
        if gist_link.lower() == 'exit':
            sign = False

