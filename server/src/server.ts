import express, { Request, Response } from 'express'
import dotenv from 'dotenv'
dotenv.config()

import mongoose from 'mongoose'
import morgan from 'morgan'
import cors from 'cors'
import routes from './routes/Routes'
import User from './models/User'
import cookieParser from 'cookie-parser'

const app = express()

app.disable('x-powered-by')
	.use(morgan('dev'))
	.use(express.urlencoded({ extended: true }))
	.use(express.json())
	.use(cors())
	.use(cookieParser())
	.use(express.static('public'))

// Connect to the database
const connectToDatabase = async () => {
	if (process.env.MONGODB_URI) {
		await mongoose
			.connect(process.env.MONGODB_URI)
			.then(() => console.info('MongoDB connected'))
			.catch((err: Error) => console.error('MongoDB connection error:', err))
	}
}
connectToDatabase()

// Set EJS as the view engine
app.set('view engine', 'ejs')
// app.set('public', './views')

// Define routes
app.use('/api', routes)

app.get('/', User.getInfo, (req: Request, res: Response) => {
	const user = req.body.user
	res.render('index', {
		page: 'Home',
		params: {
			title: 'Home Page',
			user,
			links: user ? null : [{ text: 'Login', href: '/login' }]
		}
	})
})

app.get('/login', User.getInfo, (req: Request, res: Response) => {
	return req.body.user
		? res.redirect('/')
		: res.render('index', {
				page: 'Login',
				params: {
					title: 'Login',
					scripts: ['login'],
					styles: ['forms'],
					links: [{ text: 'Home', href: '/' }]
				}
			})
})

app.get('/register', User.getInfo, (req: Request, res: Response) => {
	return req.body.user
		? res.redirect('/')
		: res.render('index', {
				page: 'Register',
				params: {
					title: 'Register',
					scripts: ['register', 'login'],
					styles: ['forms'],
					links: [{ text: 'Home', href: '/' }]
				}
			})
})

app.get('/user-profile', User.authenticate, (req: Request, res: Response) => {
	const user = req.body.user
	res.render('index', { page: 'Profile', params: { title: 'User Profile', user, scripts: ['updateProfile'], styles: ['forms'] } })
})

// Start the server
const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
	console.info(`Server is running on http://localhost:${PORT}`)
})
