import express, { Request, Response, NextFunction } from 'express'
import dotenv from 'dotenv'
import mongoose from 'mongoose'
import morgan from 'morgan'
import cors from 'cors'
import User from './models/User'

dotenv.config()

const app = express()

app.disable('x-powered-by')
	.use(morgan('dev'))
	.use(express.urlencoded({ extended: true }))
	.use(express.json())
	.use(cors())

// Connect to the database
const connectToDatabase = async () => {
	if (process.env.MONGODB_URI) {
		await mongoose.connect(process.env.MONGODB_URI)
			.then(() => console.log('MongoDB connected'))
			.catch((err: Error) => console.error('MongoDB connection error:', err));
	}
}
connectToDatabase()

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', './src/pages')

app.get('/', (req: Request, res: Response) => {
	res.render('home')
})

app.get('/login', (req: Request, res: Response) => {
	res.render('login')
})

app.get('/health', (req: Request, res: Response) => {
	res.json({ ok: true })
})


// Middleware for authentication
app.use(User.authenticate)

app.get('/protected', (req: Request, res: Response) => {
	res.send('You are authenticated')
})

const PORT = process.env.PORT || 5500

app.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`)
})