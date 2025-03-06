from selenium import webdriver
from selenium.common import StaleElementReferenceException, ElementNotInteractableException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import requests
from bs4 import BeautifulSoup
from webdriver_manager.chrome import ChromeDriverManager

# ask for gist link
def prompt_gist_link():
    return input("Enter Gist link: ").strip()

def fetch_gist_content(gist_url):
    response = requests.get(gist_url)
    return response.text if response.status_code == 200 else None

def parse_gist(html_content):
    soup = BeautifulSoup(html_content, "html.parser")

    article = soup.find("article", class_="markdown-body entry-content container-lg")
    if not article:
        print("No article found")
        return {}

    # get product and version
    product_list = article.find("ul", dir="auto")
    if product_list:
        li_tags = product_list.find_all("li")  # get all <li>
        product = li_tags[0].text.replace("Product:", "").strip() if len(li_tags)>0 else "Unknown"
        version = li_tags[1].text.replace("Version:", "").strip() if len(li_tags)>1 else "Unknown"
    else:
        print("No product and version found")
        product = "Unknown"
        version = "Unknown"

    # get location/components
    location = "Unknown"
    location_div = article.find("div", class_="highlight highlight-source-js", dir="auto")
    if location_div:
        location_span = location_div.find_all("span") # get all <span>
        location ="".join(span.text for span in location_span).strip()

    # get description
    description = "Unknown"
    description_p_tags = article.find_all("p", dir="auto") # get all <p> tags
    description = description_p_tags[4].text.strip() if len(description_p_tags) > 4 else "Unknown"

    # get attack vectors
    attack_vector = "Unknown"
    code_tags = article.find_all("code") # get all <code>
    if len(code_tags) > 1:
        attack_vector = code_tags[1].text.strip()

    return {
        "product": product,
        "version": version,
        "location": location,
        "description": description,
        "attack vector": attack_vector,
    }

def setup_webdriver():
    options = webdriver.ChromeOptions()
    options.add_argument("--start-maximized") # maximize window
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.get("https://cveform.mitre.org/")  # open up the page
    return driver

def safe_fill_element(driver, by, identifier, value, max_retries=3):
    attempt = 0
    while attempt < max_retries:
        try:
            element = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((by, identifier)))
            if element.get_attribute("value") != "":
                element.clear()
            element.send_keys(value)
            print(f"Success: {identifier} filled successfully")
            return True
        except StaleElementReferenceException:
            print(f"Attempt{attempt + 1}: Element stale, retrying")
            time.sleep(0.5)
            attempt += 1
        except ElementNotInteractableException:
            print(f"Element {identifier} not interactable, using javascript")
            input_field = driver.find_element(by, identifier)
            driver.execute_script("arguments[0].value = arguments[1];", input_field, value)
            return True
    print(f"not able to fill {identifier} after {max_retries} retries")
    return False

def form_filler(driver, parse_data, GIST_URL):
    # select a request type
    request_type = driver.find_element(By.ID, "DropDownListRequestType")
    request_type.send_keys("Report Vulnerability/Request CVE ID")

    # enter email address
    safe_fill_element(driver, By.ID, "TextBoxEmail", "Fuzzproto@gmail.com")
    print("DEBUG: email filled successfully")

    # required checkboxes
    cna_verified = driver.find_element(By.ID, "CheckBoxCnaVerified")
    if not cna_verified.is_selected():
        cna_verified.click()
    cve_verified = driver.find_element(By.ID, "CheckBoxCveAssigned")
    if not cve_verified.is_selected():
        cve_verified.click()

    # vulnerability type
    safe_fill_element(driver, By.ID, "DropDownListVulnerabilityType", "Other or Unknown")
    time.sleep(1)
    safe_fill_element(driver, By.ID, "TextBoxOtherVulnerabilityType", "CWE-1321")

    # vendor, product, product version
    safe_fill_element(driver, By.ID, "TextBoxVendor", parse_data["product"])
    safe_fill_element(driver, By.ID, "TextBoxProdCodeBase", parse_data["product"])
    safe_fill_element(driver, By.ID, "TextBoxVersions", parse_data["version"])

    # attack type
    safe_fill_element(driver, By.ID, "DropDownListAttack", "Remote")

    # impact check box
    for impact_id in ["RepeaterSingleForms_CheckBoxListImpact_0_0_0",
                      "RepeaterSingleForms_CheckBoxListImpact_0_1_0"]:
        try:
            impact_checkbox = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, impact_id)))
            if not impact_checkbox.is_selected():
                impact_checkbox.click()
            time.sleep(0.5)
        except StaleElementReferenceException:
            print(f"Element {impact_id} stale, retrying...")
            impact_checkbox = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, impact_id)))
            if not impact_checkbox.is_selected():
                impact_checkbox.click()

    time.sleep(0.5)
    # affected components
    safe_fill_element(driver, By.ID, "RepeaterSingleForms_TextBoxAffectedComponents_0", parse_data["location"])
    # attack vectors
    safe_fill_element(driver, By.ID, "RepeaterSingleForms_TextBoxAttackVectors_0", parse_data["attack vector"])
    # suggested description
    safe_fill_element(driver, By.ID, "RepeaterSingleForms_TextBoxOwnDescription_0", parse_data["description"])
    # discoverer
    safe_fill_element(driver, By.ID, "RepeaterSingleForms_TextBoxDiscoverer_0", "Tariq Hawis")
    # reference
    safe_fill_element(driver, By.ID, "RepeaterSingleForms_TextBoxReferences_0", GIST_URL)

    print("Completed")
    input("Please enter CAPCHA manually then press enter to close the browser...")


def main():
    GIST_URL = prompt_gist_link()
    html_content = fetch_gist_content(GIST_URL)
    if not html_content:
        print("No gist content")
        return

    parse_data = parse_gist(html_content)
    #print("DEBUG: parse_data =", parse_data)

    # print("\nParsed gist content:")
    # for key, value in parse_data.items():
    #     print(f"{key}: {value}")
    driver = setup_webdriver()

    try:
        form_filler(driver, parse_data, GIST_URL)
    except Exception as e:
        print("Error encountered", e)
        input("Press any key to close the browser...")
    finally:
        driver.quit()


if __name__ == "__main__":
    main()











