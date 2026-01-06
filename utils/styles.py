import streamlit as st

def load_custom_font():
    st.markdown("""
        <style>
        

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