import zipfile
import json
import zipfile
import re
from typing import Dict, Tuple, Optional
import argparse

TEXT_WEIGHT=1
URL_WEIGHT=1
SUBJECT_WEIGHT=1
SENDER_WEIGHT=1
ATTACHMENT_WEIGHT=2
PHISHING_LIMIT=3

fish_list=[]

class EmailClassifier:
    def __init__(self):

        # Ключевые слова
        self.phishing_patterns = [
            r'срочно|немедлен|быстр|обязатель', # Срочность
            r'пароль', # Данные |учетн|логин
            r'подтвер|провер|требует|нажат|нажм|обнов', # Подтверждения
            r'банк|платеж|счет|счёт|финанс', # Финансы
            r'безопасн|взлом|атак', # Безопасность
            r'приз|выигрыш|побед|лотер', # Победитель
            r'ограничен|блокир|отмен|отказ', # Угроза блокировки
            r'http://', # Ссылки
            r'ссылк|сайт', # Ссылки
            r'\d{16}',  # Номер кредитной карты
        ]

        self.URLcheck = [
            r'http://|https://',  # URL в тексте
        ]      
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.phishing_patterns]
        self.compiled_URL = [re.compile(pattern, re.IGNORECASE) for pattern in self.URLcheck]

    def is_valid_email(self, email_data: Dict) -> bool:
        if not email_data or not isinstance(email_data, dict):
            return False
        required_fields = ['id', 'datetime', 'sender', 'subject', 'attachment', 'text']

        return all(field in email_data for field in required_fields)

    def safe_lower(self, text: Optional[str]) -> str:
        if text is None:
            return ''
        return str(text).lower()

    def analyze_email(self, name, email_data: Dict) -> bool:
        # if not self.is_valid_email(email_data):
        #     return False

        phishing_score = 0
        URL_score = 0
        
        # Анализ текста письма
        text = self.safe_lower(email_data.get('text'))
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                phishing_score += TEXT_WEIGHT

        # Доп. проверка на отсутсвтие ссылкок:
        for pattern in self.compiled_URL:
            if pattern.search(text):
                URL_score += 1
        if URL_score == 0:
            phishing_score -= URL_WEIGHT

        # Анализ темы письма
        subject = self.safe_lower(email_data.get('subject'))
        for pattern in self.compiled_patterns:
            if pattern.search(subject):
                phishing_score += SUBJECT_WEIGHT

        # Анализ отправителя
        sender = self.safe_lower(email_data.get('sender'))
        suspicious_domains = ['free', 'gmail', 'yahoo', 'hotmail', 'mail', 'unknown']
        if any(domain in sender for domain in suspicious_domains):
            phishing_score += SENDER_WEIGHT

        # Анализ вложений
        attachment = self.safe_lower(email_data.get('attachment'))
        suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.js', '.vbs']
        if any(ext in attachment for ext in suspicious_extensions):
            phishing_score += ATTACHMENT_WEIGHT

        # print(name, " ", phishing_score)
        return phishing_score >= PHISHING_LIMIT

    def process_zip_archive(self, zip_path: str, folder_name: str) -> Tuple[int, int]:
        phishing_count = 0
        non_phishing_count = 0
        true_count=0 
        mistake_count=0
        

        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                
                for file_name in file_list:
                    if file_name.startswith(folder_name) and file_name.endswith('.json'):
                        try:
                            with zip_ref.open(file_name) as file:
                                content = file.read().decode('utf-8')
                                email_data = json.loads(content)
                                if not self.is_valid_email(email_data):
                                    print(file_name, "has invalid data")
                                else:
                                    if self.analyze_email(file_name, email_data):
                                        fish_list.append(file_name)
                                        phishing_count += 1
                                    else:
                                        non_phishing_count += 1
                                    
                        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as e:
                            print(f"Ошибка при обработке файла {file_name}: {e}")
                            continue
                        except Exception as e:
                            print(f"Неожиданная ошибка при обработке файла {file_name}: {e}")
                            continue
                            
        except zipfile.BadZipFile:
            print("Ошибка: файл не является корректным zip-архивом")
            return 0, 0
        except FileNotFoundError:
            print("Ошибка: файл не найден")
            return 0, 0
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")
            return 0, 0

        return phishing_count, non_phishing_count, true_count, mistake_count

def main():
    parser = argparse.ArgumentParser(description='Классификатор писем на фишинговые и не фишинговые')
    parser.add_argument('zip_file', help='Путь к zip-архиву с письмами')
    parser.add_argument('--folder', '-f', help='Папка с письмами внутри архива (опционально)')

    args = parser.parse_args()

    if not args.folder.endswith('/'):
        folder = args.folder + '/'
    else:
        folder = args.folder
    
    classifier = EmailClassifier()
    phishing, non_phishing, true_count, mistake_count = classifier.process_zip_archive(args.zip_file, folder) # , true_count, mistake_count 
    
    print(f"Фишинговые письма: {phishing}")
    print(f"Не фишинговые письма: {non_phishing}")

    for mail in fish_list:
        print(mail)

if __name__ == "__main__":
    main()
