import React from 'react'
import ReactDOM from 'react-dom'
import { BrowserRouter as Router, Route } from 'react-router-dom'

import './styles.scss'

import App from './App'
import HomePage from 'pages/home/HomePage'
import LoginPage from 'pages/login/LoginPage'

ReactDOM.render(
	<Router>
		<header>
			<h1>Client App</h1>
			<nav>
				{/* Add navigation links here */}
			</nav>
		</header>
		<React.StrictMode>
			<Route path='/' exact component={App} />
			<Route path='/home' component={HomePage} />
			<Route path='/login' component={LoginPage} />
		</React.StrictMode>
	</Router>,
	document.getElementById('root')
)