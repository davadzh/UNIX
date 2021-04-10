import json
import logging
import random
import socket
import threading
from typing import Dict, Union, Any
import sha3
from data_processing import DataProcessing
from server_validator import port_validation, check_port_open

END_MESSAGE_FLAG = "CRLF"
DEFAULT_PORT = 9090

logging.basicConfig(
    format="%(asctime)-15s [%(levelname)s] %(funcName)s: %(message)s",
    handlers=[logging.FileHandler("./logs/server.log"), logging.StreamHandler()],
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def hash(password: str) -> str:
    return sha3.sha3_224(password.encode("utf-8")).hexdigest()


class Server:
    def __init__(self, port_number: int) -> None:

        logging.info(f"Инициализация сервера")
        self.port_number = port_number
        self.sock = None
        self.database = DataProcessing()
        self.socket_init()

        self.authenticated_list = []
        self.reg_list = []
        self.connections_list = []

        self.ip2username_dict = {}
        logging.info(f"Сервер запущен на порту {port_number}")

        while True:
            conn, addr = self.sock.accept()
            self.connections_list.append((conn, addr))
            logging.info(f"Подключение от нового адреса: {addr[0]}")
            t = threading.Thread(target=self.router, args=(conn, addr))
            t.daemon = True
            t.start()

    def send_message(self, conn, data: Union[str, Dict[str, Any]], ip: str) -> None:
        data_text = data
        if type(data) == dict:
            data = json.dumps(data, ensure_ascii=False)

        data = data.encode()
        conn.send(data)
        logging.info(f"На адрес {ip} было отправлено сообщение {data_text}")

    def socket_init(self):
        sock = socket.socket()
        sock.bind(("", self.port_number))
        sock.listen(0)
        self.sock = sock

    def message_logic(self, conn, client_ip):
        data = ""
        while True:
            chunk = conn.recv(1024)
            data += chunk.decode()

            if END_MESSAGE_FLAG in data:

                username = self.ip2username_dict[client_ip]
                logging.info(
                    f"От клиента {client_ip} ({username}) получено сообщение: {data} "
                )
                data = {"username": username, "text": data}

                logger.info(
                    f"Количество подключений к серверу: {len(self.connections_list)}"
                )
                for connection in self.connections_list:
                    current_conn, current_ip = connection
                    try:
                        self.send_message(current_conn, data, current_ip)
                    except BrokenPipeError:
                        continue

                data = ""

            else:
                logger.info(f"От клиента {client_ip} была принята часть данных: '{data}'")

            if not chunk:
                break

    def reg_logic(self, conn, addr):
        data = json.loads(conn.recv(1024).decode())
        newuser_password, newuser_username = hash(data["password"]), data["username"]
        newuser_ip = addr[0]
        self.database.user_reg(newuser_ip, newuser_password, newuser_username)
        logger.info(f"Зарегистрирован новый клиент: {newuser_ip}")
        data = {"result": True}
        if newuser_ip in self.reg_list:
            self.reg_list.remove(newuser_ip)
            logging.info(f"Клиент {newuser_ip} был удален из списка регистрации")

        self.send_message(conn, data, newuser_ip)
        logger.info(f"По клиенту {newuser_ip} были отправлены данные о результате регистрации")

    def auth_logic(self, conn, addr):
        user_password = hash(json.loads(conn.recv(1024).decode())["password"])
        client_ip = addr[0]

        # Проверяем на существование данных
        auth_result, username = self.database.user_auth(client_ip, user_password)

        # Если авторизация прошла успешно
        if auth_result == 1:
            logger.info(f"Клиент {client_ip} был авторизован")
            data = {"result": True, "body": {"username": username}}
            if client_ip not in self.authenticated_list:
                self.authenticated_list.append(client_ip)
                self.ip2username_dict[client_ip] = username
                logging.info(f"Клиент {client_ip} был добавлен в список авторизации")
        # Если авторизация не удалась, но пользователь с таким ip существует
        elif auth_result == 0:
            logger.info(f"Клиент {client_ip} не был авторизован")
            data = {"result": False, "description": "wrong auth"}
        # Если пользователя с таким ip не существует, то необходима регистрация
        else:
            logger.info(
                f"Клиент {client_ip} нуждается в предварительной регистрации в системе"
            )
            data = {"result": False, "description": "registration required"}
            if client_ip not in self.reg_list:
                self.reg_list.append(client_ip)
                logging.info(f"Клиент {client_ip} был добавлен в список регистрации")

        self.send_message(conn, data, client_ip)
        logger.info(f"По клиенту {client_ip} были отправлены данные о результате авторизации")

        if auth_result == 1:
            self.message_logic(conn, client_ip)

    def router(self, conn, addr):
        logger.info("Router запущен в отдельном потоке")
        client_ip = addr[0]

        if client_ip in self.reg_list:
            self.reg_logic(conn, addr)

        elif client_ip not in self.authenticated_list:
            self.auth_logic(conn, addr)

        else:
            self.message_logic(conn, client_ip)

        logging.info(f"Отключение клиента {client_ip}")
        self.connections_list.remove((conn, addr))
        if client_ip in self.authenticated_list:
            self.authenticated_list.remove(client_ip)
            print("Список соединений:")
            print(self.connections_list)
            logging.info(f"Клиент {client_ip} был удален из списка авторизации")

    def __del__(self):
        logging.info(f"Сервер был остановлен")


def main():
    port_input = input("Укажите номер порта, на котором будет запущен сервер: ")
    port_flag = port_validation(port_input, check_open=True)

    if not port_flag:

        if not check_port_open(DEFAULT_PORT):
            print(
                f"Порт {DEFAULT_PORT} (по умолчанию) уже занят другим процессом. Производим поиск свободных портов....."
            )
            stop_flag = False
            while not stop_flag:
                current_port = random.randint(49152, 65535)
                print(f"Сгенерирован новый порт {current_port}")
                stop_flag = check_port_open(current_port)

            port_input = current_port
        else:
            port_input = DEFAULT_PORT
        print(f"Установлен порт по умолчанию: {port_input}")

    server = Server(int(port_input))


if __name__ == "__main__":
    main()
