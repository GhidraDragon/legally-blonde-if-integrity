import os
import time
import requests
import tarfile
import glob
import shutil
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess

image_count = 0

def scroll_to_end(driver, pause=2):
    last_height = driver.execute_script("return document.body.scrollHeight")
    while True:
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(pause)
        new_height = driver.execute_script("return document.body.scrollHeight")
        if new_height == last_height:
            break
        last_height = new_height

def scrape_flowers():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/106.0.0.0 Safari/537.36"
    )
    driver = webdriver.Chrome(options=options)
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

    if not os.path.exists("flowers"):
        os.makedirs("flowers")

    global image_count
    wait = WebDriverWait(driver, 10)

    google_urls = [
        "https://www.google.com/search?q=flower&start=0&udm=2#vhid=DFZ9-oMYIQPStM&vssid=mosaic",
        "https://www.google.com/search?q=flower&start=0&udm=2#vhid=RLjZqDI96V5HcM&vssid=mosaic"
    ]
    for url in google_urls:
        driver.get(url)
        time.sleep(2)
        try:
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(),'Accept all')]"))
            ).click()
            time.sleep(1)
        except:
            pass
        while True:
            scroll_to_end(driver)
            thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.Q4LuWd")
            for thumb in thumbnails:
                src = thumb.get_attribute("src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-iurl")
                if src and "http" in src:
                    try:
                        r = requests.get(src, timeout=5)
                        temp_path = "temp_google.jpg"
                        with open(temp_path, "wb") as f:
                            f.write(r.content)
                        try:
                            with Image.open(temp_path) as img_check:
                                pass
                            path = f"flowers/flower_{image_count}.jpg"
                            shutil.move(temp_path, path)
                            image_count += 1
                        except:
                            os.remove(temp_path)
                    except:
                        pass
            try:
                next_button = driver.find_element(By.ID, "pnnext")
                next_button.click()
                time.sleep(2)
            except:
                break

    if image_count == 0:
        for start in range(0, 100, 20):
            page_url = f"https://www.google.com/search?tbm=isch&q=flower&start={start}"
            driver.get(page_url)
            time.sleep(2)
            try:
                wait.until(EC.element_to_be_clickable(
                    (By.XPATH, "//button[contains(text(),'Accept all')]"))
                ).click()
                time.sleep(1)
            except:
                pass
            scroll_to_end(driver)
            thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.Q4LuWd")
            for thumb in thumbnails:
                src = thumb.get_attribute("src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-iurl")
                if src and "http" in src:
                    try:
                        r = requests.get(src, timeout=5)
                        temp_path = "temp_google.jpg"
                        with open(temp_path, "wb") as f:
                            f.write(r.content)
                        try:
                            with Image.open(temp_path) as img_check:
                                pass
                            path = f"flowers/flower_{image_count}.jpg"
                            shutil.move(temp_path, path)
                            image_count += 1
                        except:
                            os.remove(temp_path)
                    except:
                        pass

    if image_count == 0:
        for start in range(0, 100, 20):
            bing_url = f"https://www.bing.com/images/search?q=flower&first={start}"
            driver.get(bing_url)
            time.sleep(2)
            try:
                driver.find_element(By.ID, "bnp_btn_accept").click()
                time.sleep(1)
            except:
                pass
            scroll_to_end(driver)
            thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.mimg")
            for thumb in thumbnails:
                src = thumb.get_attribute("src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-src")
                if src and "http" in src:
                    try:
                        r = requests.get(src, timeout=5)
                        temp_path = "temp_bing.jpg"
                        with open(temp_path, "wb") as f:
                            f.write(r.content)
                        try:
                            with Image.open(temp_path) as img_check:
                                pass
                            path = f"flowers/flower_{image_count}.jpg"
                            shutil.move(temp_path, path)
                            image_count += 1
                        except:
                            os.remove(temp_path)
                    except:
                        pass

    if image_count == 0:
        page_url = "https://duckduckgo.com/?q=flower&iax=images&ia=images"
        driver.get(page_url)
        time.sleep(2)
        scroll_to_end(driver, pause=2)
        thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.tile--img__img")
        for thumb in thumbnails:
            src = thumb.get_attribute("src")
            if not (src and "http" in src):
                src = thumb.get_attribute("data-src")
            if src and "http" in src:
                try:
                    r = requests.get(src, timeout=5)
                    temp_path = "temp_duckduckgo.jpg"
                    with open(temp_path, "wb") as f:
                        f.write(r.content)
                    try:
                        with Image.open(temp_path) as img_check:
                            pass
                        path = f"flowers/flower_{image_count}.jpg"
                        shutil.move(temp_path, path)
                        image_count += 1
                    except:
                        os.remove(temp_path)
                except:
                    pass

    driver.quit()

def scrape_plural_flowers():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/106.0.0.0 Safari/537.36"
    )
    driver = webdriver.Chrome(options=options)
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

    if not os.path.exists("plural_flowers"):
        os.makedirs("plural_flowers")

    global image_count
    wait = WebDriverWait(driver, 10)

    google_urls = [
        "https://www.google.com/search?q=flowers&start=0&udm=2#vhid=DFZ9-oMYIQPStM&vssid=mosaic",
        "https://www.google.com/search?q=flowers&start=0&udm=2#vhid=RLjZqDI96V5HcM&vssid=mosaic"
    ]
    for url in google_urls:
        driver.get(url)
        time.sleep(2)
        try:
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(),'Accept all')]"))
            ).click()
            time.sleep(1)
        except:
            pass
        while True:
            scroll_to_end(driver)
            thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.Q4LuWd")
            for thumb in thumbnails:
                src = thumb.get_attribute("src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-src")
                if not (src and "http" in src):
                    src = thumb.get_attribute("data-iurl")
                if src and "http" in src:
                    try:
                        r = requests.get(src, timeout=5)
                        temp_path = "temp_google_plural.jpg"
                        with open(temp_path, "wb") as f:
                            f.write(r.content)
                        try:
                            with Image.open(temp_path) as img_check:
                                pass
                            path = f"plural_flowers/flowers_{image_count}.jpg"
                            shutil.move(temp_path, path)
                            image_count += 1
                        except:
                            os.remove(temp_path)
                    except:
                        pass
            try:
                next_button = driver.find_element(By.ID, "pnnext")
                next_button.click()
                time.sleep(2)
            except:
                break

    # Removed the 'if image_count == 0' check here so it always attempts additional pages
    for start in range(0, 100, 20):
        page_url = f"https://www.google.com/search?tbm=isch&q=flowers&start={start}"
        driver.get(page_url)
        time.sleep(2)
        try:
            wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(),'Accept all')]"))
            ).click()
            time.sleep(1)
        except:
            pass
        scroll_to_end(driver)
        thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.Q4LuWd")
        for thumb in thumbnails:
            src = thumb.get_attribute("src")
            if not (src and "http" in src):
                src = thumb.get_attribute("data-src")
            if not (src and "http" in src):
                src = thumb.get_attribute("data-iurl")
            if src and "http" in src:
                try:
                    r = requests.get(src, timeout=5)
                    temp_path = "temp_google_plural.jpg"
                    with open(temp_path, "wb") as f:
                        f.write(r.content)
                    try:
                        with Image.open(temp_path) as img_check:
                            pass
                        path = f"plural_flowers/flowers_{image_count}.jpg"
                        shutil.move(temp_path, path)
                        image_count += 1
                    except:
                        os.remove(temp_path)
                except:
                    pass

    for start in range(0, 100, 20):
        bing_url = f"https://www.bing.com/images/search?q=flowers&first={start}"
        driver.get(bing_url)
        time.sleep(2)
        try:
            driver.find_element(By.ID, "bnp_btn_accept").click()
            time.sleep(1)
        except:
            pass
        scroll_to_end(driver)
        thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.mimg")
        for thumb in thumbnails:
            src = thumb.get_attribute("src")
            if not (src and "http" in src):
                src = thumb.get_attribute("data-src")
            if src and "http" in src:
                try:
                    r = requests.get(src, timeout=5)
                    temp_path = "temp_bing_plural.jpg"
                    with open(temp_path, "wb") as f:
                        f.write(r.content)
                    try:
                        with Image.open(temp_path) as img_check:
                            pass
                        path = f"plural_flowers/flowers_{image_count}.jpg"
                        shutil.move(temp_path, path)
                        image_count += 1
                    except:
                        os.remove(temp_path)
                except:
                    pass

    page_url = "https://duckduckgo.com/?q=flowers&iax=images&ia=images"
    driver.get(page_url)
    time.sleep(2)
    scroll_to_end(driver, pause=2)
    thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.tile--img__img")
    for thumb in thumbnails:
        src = thumb.get_attribute("src")
        if not (src and "http" in src):
            src = thumb.get_attribute("data-src")
        if src and "http" in src:
            try:
                r = requests.get(src, timeout=5)
                temp_path = "temp_duckduckgo_plural.jpg"
                with open(temp_path, "wb") as f:
                    f.write(r.content)
                try:
                    with Image.open(temp_path) as img_check:
                        pass
                    path = f"plural_flowers/flowers_{image_count}.jpg"
                    shutil.move(temp_path, path)
                    image_count += 1
                except:
                    os.remove(temp_path)
            except:
                pass

    driver.quit()

def download_oxford_102_flowers():
    url = "https://www.robots.ox.ac.uk/~vgg/data/flowers/102/102flowers.tgz"
    if not os.path.exists("temp"):
        os.makedirs("temp")
    tgz_path = os.path.join("temp", "102flowers.tgz")
    if not os.path.exists(tgz_path):
        r = requests.get(url, stream=True)
        with open(tgz_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    with tarfile.open(tgz_path, "r:gz") as t:
        t.extractall("temp/oxford_flowers")
    flist = glob.glob("temp/oxford_flowers/**/*.jpg", recursive=True)
    global image_count
    if not os.path.exists("flowers"):
        os.makedirs("flowers")
    for file in flist:
        try:
            with Image.open(file) as im:
                pass
            newpath = f"flowers/flower_{image_count}.jpg"
            shutil.copy(file, newpath)
            image_count += 1
        except:
            pass

def download_kaggle_flowers():
    if not os.path.exists("temp_kaggle"):
        os.makedirs("temp_kaggle")
    try:
        subprocess.run([
            "kaggle", "datasets", "download", "-d", "alxmamaev/flowers",
            "-p", "temp_kaggle", "--unzip"
        ], check=True)
    except:
        pass
    global image_count
    if not os.path.exists("flowers"):
        os.makedirs("flowers")
    for root, dirs, files in os.walk("temp_kaggle"):
        for f in files:
            if f.lower().endswith((".jpg", ".jpeg", ".png")):
                path = os.path.join(root, f)
                try:
                    with Image.open(path) as im:
                        pass
                    newpath = f"flowers/flower_{image_count}.jpg"
                    shutil.copy(path, newpath)
                    image_count += 1
                except:
                    pass

def download_kaggle_flowers_emmarex():
    if not os.path.exists("temp_kaggle_emmarex"):
        os.makedirs("temp_kaggle_emmarex")
    try:
        subprocess.run([
            "kaggle", "datasets", "download", "-d", "emmarex/flowers",
            "-p", "temp_kaggle_emmarex", "--unzip"
        ], check=True)
    except:
        pass
    global image_count
    if not os.path.exists("flowers"):
        os.makedirs("flowers")
    for root, dirs, files in os.walk("temp_kaggle_emmarex"):
        for f in files:
            if f.lower().endswith((".jpg", ".jpeg", ".png")):
                path = os.path.join(root, f)
                try:
                    with Image.open(path) as im:
                        pass
                    newpath = f"flowers/flower_{image_count}.jpg"
                    shutil.copy(path, newpath)
                    image_count += 1
                except:
                    pass

def download_tensorflow_flower_photos():
    url = "https://storage.googleapis.com/download.tensorflow.org/example_images/flower_photos.tgz"
    if not os.path.exists("temp_tensorflow"):
        os.makedirs("temp_tensorflow")
    tgz_path = os.path.join("temp_tensorflow", "flower_photos.tgz")
    if not os.path.exists(tgz_path):
        r = requests.get(url, stream=True)
        with open(tgz_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    with tarfile.open(tgz_path, "r:gz") as t:
        t.extractall("temp_tensorflow/flower_photos")
    flist = glob.glob("temp_tensorflow/flower_photos/**/*.jpg", recursive=True)
    global image_count
    if not os.path.exists("flowers"):
        os.makedirs("flowers")
    for file in flist:
        try:
            with Image.open(file) as im:
                pass
            newpath = f"flowers/flower_{image_count}.jpg"
            shutil.copy(file, newpath)
            image_count += 1
        except:
            pass

if __name__ == "__main__":
    scrape_flowers()
    scrape_plural_flowers()
    download_oxford_102_flowers()
    download_kaggle_flowers()
    download_kaggle_flowers_emmarex()
    download_tensorflow_flower_photos()
    print(f"Total images downloaded: {image_count}")