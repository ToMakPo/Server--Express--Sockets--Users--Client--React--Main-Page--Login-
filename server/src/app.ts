import express from 'express';

const app = express();
const port = 5000;

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', './src/pages')

// Middleware to parse JSON bodies
app.use(express.json());

// Basic route
app.get('/', (req, res) => {
    res.render('home', { title: 'HomeX' });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});