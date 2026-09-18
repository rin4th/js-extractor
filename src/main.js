import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';

const target = document.getElementById('app');

if (!target) {
  throw new Error('Unable to find the application mount point.');
}

const app = mount(App, { target });

export default app;
