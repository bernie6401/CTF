import { marked } from 'https://esm.run/marked'
import * as DOMPurify from 'https://esm.run/dompurify'

class MdText extends HTMLElement {
  connectedCallback() {
    this.innerHTML = marked(this.textContent) //DOMPurify.sanitize(marked(this.textContent))
  }
}

customElements.define('md-text', MdText)
