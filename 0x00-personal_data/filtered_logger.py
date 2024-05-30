#!/usr/bin/env python3
"""
Module for filtering log data and securely logging PII data
"""

import re
import os
import logging
import mysql.connector
from typing import List

# Task 0: Regex-ing
def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Replaces values of specified fields in the log message with a redaction string.

    Args:
        fields (List[str]): List of field names to redact.
        redaction (str): The string to replace the field values with.
        message (str): The log message.
        separator (str): The field separator in the log message.

    Returns:
        str: The redacted log message.
    """
    for field in fields:
        message = re.sub(r'{}=.*?{}'.format(field, separator), '{}={}'.format(field, redaction), message)
    return message


# Task 1: Log formatter
class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record and filter the sensitive information.

        Args:
            record (logging.LogRecord): The log record.

        Returns:
            str: The formatted log record.
        """
        record.msg = filter_datum(self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


# Task 2: Create logger
PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def get_logger() -> logging.Logger:
    """
    Creates a logger named "user_data" that only logs up to logging.INFO level.

    Returns:
        logging.Logger: The logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


# Task 3: Connect to secure database
def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Connects to the MySQL database using credentials from environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: The database connection object.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=db_name
    )


# Task 4: Read and filter data
def main():
    """
    Retrieves all rows from the users table and displays each row
    under a filtered format.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    field_names = [i[0] for i in cursor.description]

    logger = get_logger()

    for row in cursor:
        message = '; '.join(f"{field}={value}" for field, value in zip(field_names, row)) + ';'
        logger.info(message)

    cursor.close()
    db.close()

if __name__ == "__main__":
    main()

