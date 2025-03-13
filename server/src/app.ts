import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

// Load environment variables from .env file
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Connect to the database
if (process.env.MONGODB_URI) {
	await mongoose.connect(process.env.MONGODB_URI)
		.then(() => console.log('MongoDB connected'))
		.catch((err: Error) => console.error('MongoDB connection error:', err));
}

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', './src/pages')

// Middleware to parse JSON bodies
app.use(express.json());

// Basic route
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/login', (req, res) => {
	res.render('login');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});