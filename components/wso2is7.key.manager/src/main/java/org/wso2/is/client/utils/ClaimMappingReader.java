/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.client.utils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.apimgt.api.APIManagementException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.apimgt.impl.utils.APIUtil.handleException;

/**
 * This class is used to read claim mappings from the claim-config.xml file.
 */
public class ClaimMappingReader {

    private static final String CLAIM_CONFIG_XML_FILE = "claim-config.xml";
    private static final String DIALECT_XML_TAG_NAME = "Dialect";
    private static final String DIALECT_URI_ATTRIBUTE_NAME = "dialectURI";
    private static final String CLAIM_XML_TAG_NAME = "Claim";
    private static final String CLAIM_URI_XML_TAG_NAME = "ClaimURI";
    private static final String MAPPED_LOCAL_CLAIM_XML_TAG_NAME = "MappedLocalClaim";
    private static final String SCIM2_CORE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0";
    private static final String SCIM2_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final String SCIM2_ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";


    /**
     * Loads claim mappings from the claim-config.xml file.
     * @return                          A map of claim URI to mapped local claim.
     * @throws APIManagementException   If an error occurs while obtaining claim mappings.
     */
    public static Map<String, String> loadClaimMappings() throws APIManagementException {
        Map<String, String> claimMappings = new HashMap<>();
        try {
            InputStream inputStream = ClaimMappingReader.class.getClassLoader()
                    .getResourceAsStream(CLAIM_CONFIG_XML_FILE);
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.parse(inputStream);
            document.getDocumentElement().normalize();

            // Traverse through <Dialect> nodes
            NodeList dialectNodes = document.getElementsByTagName(DIALECT_XML_TAG_NAME);
            for (int i = 0; i < dialectNodes.getLength(); i++) {
                Node dialectNode = dialectNodes.item(i);
                if (dialectNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element dialectElement = (Element) dialectNode;
                    String dialectURI = dialectElement.getAttribute(DIALECT_URI_ATTRIBUTE_NAME);
                    if (dialectURI.equals(SCIM2_CORE_SCHEMA) || dialectURI.equals(SCIM2_USER_SCHEMA) ||
                            dialectURI.equals(SCIM2_ENTERPRISE_SCHEMA)) {
                        // Traverse through <Claim> nodes
                        NodeList claimNodes = dialectElement.getElementsByTagName(CLAIM_XML_TAG_NAME);
                        for (int j = 0; j < claimNodes.getLength(); j++) {
                            Node claimNode = claimNodes.item(j);
                            if (claimNode.getNodeType() == Node.ELEMENT_NODE) {
                                Element claimElement = (Element) claimNode;
                                String claimURI = null;
                                String mappedLocalClaim = null;
                                if (claimElement.getElementsByTagName(CLAIM_URI_XML_TAG_NAME) != null &&
                                        claimElement.getElementsByTagName(CLAIM_URI_XML_TAG_NAME).item(0) != null) {
                                    claimURI = claimElement.getElementsByTagName(CLAIM_URI_XML_TAG_NAME).item(0)
                                            .getTextContent();
                                }
                                if (claimElement.getElementsByTagName(MAPPED_LOCAL_CLAIM_XML_TAG_NAME) != null &&
                                        claimElement.getElementsByTagName(MAPPED_LOCAL_CLAIM_XML_TAG_NAME)
                                                .item(0) != null) {
                                    mappedLocalClaim = claimElement
                                            .getElementsByTagName(MAPPED_LOCAL_CLAIM_XML_TAG_NAME)
                                            .item(0)
                                            .getTextContent();
                                }
                                if (claimURI != null && mappedLocalClaim != null) {
                                    claimMappings.put(claimURI, mappedLocalClaim);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            handleException("Error occurred while obtaining claim configs", e);
        }
        return claimMappings;
    }


    // TODO Implement AttributeSchema Mapping
//    public static Map<String, List<AttributeSchema>> getSchemasAndAttributes() throws APIManagementException {
//        Map<String, List<AttributeSchema>> schemasAndAttributes = new HashMap<>();
//        try {
//            InputStream inputStream = ClaimMappingReader.class.getClassLoader()
//                    .getResourceAsStream(CLAIM_CONFIG_XML_FILE);
//            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
//            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
//            Document document = documentBuilder.parse(inputStream);
//            document.getDocumentElement().normalize();
//
//            // Traverse through <Dialect> nodes
//            NodeList dialectNodes = document.getElementsByTagName(DIALECT_XML_TAG_NAME);
//            for (int i = 0; i < dialectNodes.getLength(); i++) {
//                Node dialectNode = dialectNodes.item(i);
//                if (dialectNode.getNodeType() == Node.ELEMENT_NODE) {
//                    Element dialectElement = (Element) dialectNode;
//                    String dialectURI = dialectElement.getAttribute(DIALECT_URI_ATTRIBUTE_NAME);
//                    if (dialectURI.equals(SCIM2_CORE_SCHEMA) || dialectURI.equals(SCIM2_USER_SCHEMA) ||
//                            dialectURI.equals(SCIM2_ENTERPRISE_SCHEMA)) {
//
//                        List<AttributeSchema> attributeSchemas = new ArrayList<>();
//
//                        // Traverse through <Claim> nodes
//                        NodeList claimNodes = dialectElement.getElementsByTagName(CLAIM_XML_TAG_NAME);
//                        for (int j = 0; j < claimNodes.getLength(); j++) {
//                            Node claimNode = claimNodes.item(j);
//                            if (claimNode.getNodeType() == Node.ELEMENT_NODE) {
//                                Element claimElement = (Element) claimNode;
//                                String claimURI = null;
//                                String mappedLocalClaim = null;
//
//                                if (claimElement.getElementsByTagName(CLAIM_URI_XML_TAG_NAME) != null &&
//                                        claimElement.getElementsByTagName(CLAIM_URI_XML_TAG_NAME).item(0) != null) {
//                                    claimURI = claimElement.getElementsByTagName(CLAIM_URI_XML_TAG_NAME).item(0)
//                                            .getTextContent();
//                                }
//                                if (claimElement.getElementsByTagName(MAPPED_LOCAL_CLAIM_XML_TAG_NAME) != null &&
//                                        claimElement.getElementsByTagName(MAPPED_LOCAL_CLAIM_XML_TAG_NAME)
//                                                .item(0) != null) {
//                                    mappedLocalClaim = claimElement
//                                            .getElementsByTagName(MAPPED_LOCAL_CLAIM_XML_TAG_NAME)
//                                            .item(0)
//                                            .getTextContent();
//                                }
//
//
//                                String name = null;
//                                if (claimElement.getElementsByTagName("AttributeID") != null &&
//                                        claimElement.getElementsByTagName("AttributeID").item(0) != null) {
//                                    name = claimElement.getElementsByTagName("AttributeID").item(0)
//                                            .getTextContent();
//                                }
//                                SCIMDefinitions.DataType type = SCIMDefinitions.DataType.STRING;
//                                boolean multiValued = false;
//                                String description = null;
//                                if (claimElement.getElementsByTagName("Description") != null &&
//                                        claimElement.getElementsByTagName("Description").item(0) != null) {
//                                    description = claimElement.getElementsByTagName("Description").item(0)
//                                            .getTextContent();
//                                }
//                                boolean required = false;
//                                boolean caseExact = false;
//                                SCIMDefinitions.Mutability mutability = SCIMDefinitions.Mutability.READ_WRITE;
//                                SCIMDefinitions.Returned returned = SCIMDefinitions.Returned.DEFAULT;
//                                SCIMDefinitions.Uniqueness uniqueness = SCIMDefinitions.Uniqueness.NONE;
//                                ArrayList<String> canonicalValues = new ArrayList<>();
//                                ArrayList<SCIMDefinitions.ReferenceType> referenceTypes = new ArrayList<>();
//                                ArrayList<AttributeSchema> subAttributes = new ArrayList<>();
//
//                                SCIMAttributeSchema scimAttributeSchema =
//                                        SCIMAttributeSchema.createSCIMAttributeSchema(
//                                                claimURI, name, type, multiValued, description, required, caseExact,
//                                                mutability, returned, uniqueness, canonicalValues, referenceTypes,
//                                                subAttributes);
//
//                                attributeSchemas.add(scimAttributeSchema);
//                            }
//                        }
//
//                        schemasAndAttributes.put(dialectURI, attributeSchemas);
//                    }
//                }
//            }
//        } catch (Exception e) {
//            handleException("Error occurred while obtaining claim configs", e);
//        }
//        return schemasAndAttributes;
//    }

}
