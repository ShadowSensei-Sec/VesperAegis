class ConnectionTracker:

    def __init__(self):
        self.connections = {}

    def add_connection(self, connection_id, connection_data):
        self.connections[connection_id] = connection_data

    def get_connection(self, connection_id):
        return self.connections.get(connection_id)

    def remove_connection(self, connection_id):
        self.connections.pop(connection_id, None)

    def get_all_connections(self):
        return self.connections