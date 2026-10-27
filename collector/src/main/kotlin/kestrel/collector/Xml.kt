package kestrel.collector

import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import org.xml.sax.ErrorHandler
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import org.xml.sax.SAXParseException
import java.io.StringReader
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

/** 외부에서 받은 XML을 읽는다. DOCTYPE을 막아 외부 엔티티(XXE)와 엔티티 폭탄을 차단한다. */
internal object Xml {
    private val factory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        isXIncludeAware = false
        isExpandEntityReferences = false
        setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    }

    // 기본 오류 처리기는 표준 오류에 "[Fatal Error]"를 찍는다. 예외로만 알린다.
    private val quiet = object : ErrorHandler {
        override fun warning(e: SAXParseException) {}
        override fun error(e: SAXParseException) = throw e
        override fun fatalError(e: SAXParseException) = throw e
    }

    fun parse(source: String, text: String): Document = try {
        factory.newDocumentBuilder().apply { setErrorHandler(quiet) }
            .parse(InputSource(StringReader(text.trimStart('﻿', ' ', '\t', '\r', '\n'))))
    } catch (e: SAXException) {
        throw SourceFormatException(source, "XML 파싱 실패: ${e.message}", e)
    }
}

/** 바로 아래 자식 요소 중 이름(네임스페이스 포함)이 맞는 것들. */
internal fun Element.children(localName: String, ns: String? = null): List<Element> {
    val out = ArrayList<Element>()
    var n: Node? = firstChild
    while (n != null) {
        if (n is Element && n.localName == localName && n.namespaceURI == ns) out += n
        n = n.nextSibling
    }
    return out
}

internal fun Element.child(localName: String, ns: String? = null): Element? = children(localName, ns).firstOrNull()

internal fun Element.childText(localName: String, ns: String? = null): String? = child(localName, ns)?.textContent
