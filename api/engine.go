package api

import "log"

type engine struct {
	connectedUsers     map[int]*User
	Messages           []*Message `json: messages`
	addUser            chan *User
	removeUser         chan *User
	newIncomingMessage chan *Message
	errorChannel       chan error
	doneCh             chan bool
}

func newengine() *engine {
	return &engine{}
}

func (e *engine) listen() {
	for {
		select {
		// Adding a new user
		case user := <-server.addUser:
			log.Println("Added a new User")
			server.connectedUsers[user.id] = user
			log.Println("Now ", len(server.connectedUsers), " users are connected to chat room")
			server.sendPastMessages(user)

		case user := <-server.removeUser:
			log.Println("Removing user from chat room")
			delete(server.connectedUsers, user.id)

		case msg := <-server.newIncomingMessage:
			server.Messages = append(server.Messages, msg)
			server.sendAll(msg)
		case err := <-server.errorChannel:
			log.Println("Error : ", err)
		case <-server.doneCh:
			return
		}
	}
}
