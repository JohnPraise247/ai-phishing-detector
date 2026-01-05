import streamlit as st

def load_custom_font():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

        h1, h2, h3, h4, h5, h6 {
            font-family: 'Inter', sans-serif !important;
            font-weight: 400 !important;
        }
        p{
            font-family: 'Inter', sans-serif !important;
        }

        /* Mobile screens */
        @media (max-width: 768px) {
            h1 {
                font-size: 2.25rem!important;
            }
        }
        </style>
    """, unsafe_allow_html=True)