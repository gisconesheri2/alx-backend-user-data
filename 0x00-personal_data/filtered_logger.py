#!/usr/bin/env python3
"""obfuscate a log message so as to
remove personal information form log messages"""
import logging
import re
from typing import List
import mysql.connector
import os

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscate @fields in a @message with
    @redaction. fields separated by @separator
    >>> fields = ["password", "name"]
    >>> message = "name=egg;email=eggmin@eggsample.com;password=eggcellent;"
    >>> redaction = 'xxx'
    >>> filter_datum(fields, redaction, message, ';')
    >>> 'name=xxx;email=eggmin@eggsample.com;password=xxx;;'
    """
    for field in fields:
        msg_comp = message.split(separator)
        msg_comp = [re.sub(f'({field}=).*',
                           rf'\1{redaction}', msg) for msg in msg_comp]
        message = separator.join(msg_comp)
    return message


def get_logger() -> logging.Logger:
    """
    Set up handlers and formatters for the logger
    Return:
        a logger with a custom formatter
    """
    user_data = logging.getLogger('user_data')
    user_data.setLevel(logging.INFO)

    sh = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)

    sh.setFormatter(formatter)
    user_data.addHandler(sh)
    user_data.propagate = False
    return user_data


def get_db() -> mysql.connector.connection_cext.CMySQLConnection:
    """
    Setup a database connector for a MYSQL database
    use environmental variables to sensitive info
    """
    username = os.getenv('PERSONAL_DATA_DB_USERNAME')
    pwd = os.getenv('PERSONAL_DATA_DB_PASSWORD')
    host = os.getenv('PERSONAL_DATA_DB_HOST')
    db = os.getenv('PERSONAL_DATA_DB_NAME')
    try:
        cnx = mysql.connector.connect(user=username, password=pwd,
                                      host=host, database=db)
        return cnx
    except mysql.connector.Error as err:
        pass


def main():
    """get data from a database and log it with
    personal data redacted out
    """
    my_db = get_db()
    logger = get_logger()

    cursor = my_db.cursor()
    cursor.execute("SELECT * FROM users;")
    for row in cursor.fetchall():
        row_head = ['name', 'email', 'phone', 'ssn', 'password', 'ip',
                    'last_login', 'user_agent']
        row_elems = ([str(entry) for entry in row])
        rhe = list(zip(row_head, row_elems))
        logger.info('; '.join(['='.join(elem) for elem in rhe]))


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize the class"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record y redacting any personal info"""
        redacted_msg = filter_datum(self.fields, self.REDACTION,
                                    record.msg, self.SEPARATOR)
        record.msg = redacted_msg
        return super().format(record)


if __name__ == '__main__':
    main()
