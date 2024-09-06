import scrapy
import mysql.connector
from mysql.connector import Error

class LocalSpider(scrapy.Spider):
    name = 'mi_spider'
    start_urls = ['http://192.168.11.13:8000']  

    def parse(self, response):
        # Extraer los datos que te interesen
        for item in response.css('div.item'):
            yield {
                'title': item.css('h2::text').get(),
                'description': item.css('p::text').get(),
            }

        # Conectar a MySQL y guardar los datos extraídos
        self.save_to_db(response)

    def save_to_db(self, response):
        try:
            connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="root",  
                database="criptografia_db"
            )
            if connection.is_connected():
                cursor = connection.cursor()
                for item in response.css('div.item'):
                    title = item.css('h2::text').get()
                    description = item.css('p::text').get()
                    if title and description:  # Verifica que ambos valores no sean None
                        cursor.execute(
                            "INSERT INTO scraped_data (title, description) VALUES (%s, %s)",
                            (title, description)
                        )
                connection.commit()
                cursor.close()
        except Error as e:
            self.logger.error(f"Error al conectar a MySQL: {e}")
        finally:
            if connection.is_connected():
                connection.close()
