/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: { mono: ['"Courier New"', 'Courier', 'monospace'] },
      colors: {
        zk: {
          bg:      '#1e1e2e', panel:   '#252538', panel2:  '#2a2a40',
          panel3:  '#32324a', lift:    '#16162a',
          b1:      '#383855', b2:      '#44445e', b3:      '#565678',
          tx0:     '#d0d0e8', tx1:     '#a2a2be', tx2:     '#606080', tx3:     '#6a6a7e',
          green:   '#4db366', green2:  '#1e4028', green3:  '#122218',
          red:     '#e05c6e', red2:    '#3d1520',
          orange:  '#d48b55', orange2: '#3a2010',
          cyan:    '#5bb8d4', yellow:  '#c8a84b',
          purple:  '#a07fd4', blue:    '#6ea8e0', blue2:   '#1e3a5a',
        }
      }
    },
  },
  plugins: [],
}
