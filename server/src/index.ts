import { createServer } from './app'

// const PORT = process.env.PORT || 3000
const PORT = 5500
const server = createServer()

server.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`)
})