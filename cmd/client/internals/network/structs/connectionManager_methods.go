package structs

func (manager *ConnectionManager) Close() {
	manager.Once.Do(func() {
		manager.Conn.Close()
		manager.Tor.Close()
		close(manager.GlobalOut)
		close(manager.Done)
	})
}