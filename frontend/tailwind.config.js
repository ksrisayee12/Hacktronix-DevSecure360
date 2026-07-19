/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "#1B3C53",
        secondary: "#234C6A",
        accent: "#456882",
        neutral: "#D2C1B6",
        chart1: "#522258",
        chart2: "#8C3061",
        chart3: "#C63C51",
        chart4: "#D95F59",
      },
    },
  },
  plugins: [],
}
