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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.encoder.JSONDecoder;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.AbstractSCIMObject;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.AttributeUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.apimgt.impl.utils.APIUtil.handleException;

/**
 * Contains methods rleated to SCIM attribute mapping.
 * Copied from <a href="https://raw.githubusercontent.com/wso2-extensions/identity-inbound-provisioning-scim2/master/components/org.wso2.carbon.identity.scim2.common/src/main/java/org/wso2/carbon/identity/scim2/common/utils/AttributeMapper.java">AttributeMapper</a>,
 * to avoid dependency on identity-inbound-provisioning-scim2 module.
 */
public class AttributeMapper {

    private static final String ADVANCED_ATTRIBUTE_IDENTIFIER = "#";
    private static final String SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED = "SCIM2" +
            ".ComplexMultiValuedAttributeSupportEnabled";

    /**
     * Get user claims from the given SCIM object string.
     *
     * @param scimUserObjectString      SCIM 2.0 Payload of a user info.
     * @return                          A map that contains the SCIM URI and the value of the claim.
     * @throws APIManagementException   If an error occurs while decoding the SCIM object, or getting the claims.
     */
    public static Map<String, String> getUserClaims(String scimUserObjectString) throws APIManagementException {
        JSONDecoder jsonDecoder = new JSONDecoder();
        // TODO: Currently only user resource schema is supported. Need to support other resource schemas as well.
        SCIMResourceTypeSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
        Map<String, String> claims = new HashMap<>();
        try {
            User user = (User) jsonDecoder.decode(scimUserObjectString, schema);
            if (user != null) {
                claims = getClaimsMap(user);
            }
        } catch (CharonException | BadRequestException e) {
            handleException("Error while decoding the SCIM Object", e);
        }
        return claims;
    }

    /**
     * Return claims as a map of <ClaimUri (which is mapped to SCIM attribute uri),ClaimValue>.
     *
     * @param scimObject SCIM object.
     * @return A map of claims.
     */
    public static Map<String, String> getClaimsMap(AbstractSCIMObject scimObject) throws APIManagementException {
        Map<String, String> claimsMap = new HashMap<>();
        try {
            Map<String, Attribute> attributeList = scimObject.getAttributeList();
            for (Map.Entry<String, Attribute> attributeEntry : attributeList.entrySet()) {
                Attribute attribute = attributeEntry.getValue();
                // if the attribute is password, skip it
                if (SCIMConstants.UserSchemaConstants.PASSWORD.equals(attribute.getName())) {
                    continue;
                }
                if (attribute instanceof SimpleAttribute) {
                    setClaimsForSimpleAttribute(attribute, claimsMap);

                } else if (attribute instanceof MultiValuedAttribute) {
                    setClaimsForMultivaluedAttribute(attribute, claimsMap);
                } else if (attribute instanceof ComplexAttribute) {
                /*
                NOTE: in carbon, we only support storing of type and value of a complex multi-valued attribute
                reading attributes list of the complex attribute.
                 */
                    ComplexAttribute complexAttribute = (ComplexAttribute) attribute;
                    Map<String, Attribute> attributes = null;
                    if (complexAttribute.getSubAttributesList() != null &&
                            MapUtils.isNotEmpty(complexAttribute.getSubAttributesList())) {
                        attributes = complexAttribute.getSubAttributesList();
                    }
                    if (attributes != null) {
                        for (Attribute entry : attributes.values()) {
                            // if the attribute a simple attribute
                            if (entry instanceof SimpleAttribute) {
                                setClaimsForSimpleAttribute(entry, claimsMap);

                            } else if (entry instanceof MultiValuedAttribute) {
                                setClaimsForMultivaluedAttribute(entry, claimsMap);

                            } else if (entry instanceof ComplexAttribute) {
                                setClaimsForComplexAttribute(entry, claimsMap);
                            }
                        }
                    }
                }
            }
        } catch (CharonException e) {
            handleException("Error while getting claims", e);
        }
        return claimsMap;
    }

    /**
     * Set claim mapping for simple attribute.
     *
     * @param attribute Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForSimpleAttribute(Attribute attribute, Map<String, String> claimsMap)
            throws CharonException {

        String attributeURI = attribute.getURI();
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(
                    ((SimpleAttribute) attribute).getValue(), attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    /**
     * Set claim mapping for multivalued attribute.
     *
     * @param attribute Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForMultivaluedAttribute(Attribute attribute, Map<String, String> claimsMap)
            throws CharonException {

        MultiValuedAttribute multiValAttribute = (MultiValuedAttribute) attribute;
        // Get the URI of root attribute.
        String attributeURI = multiValAttribute.getURI();
        // Check if values are set as primitive values.
        List<Object> attributeValues = multiValAttribute.getAttributePrimitiveValues();
        if (CollectionUtils.isNotEmpty(attributeValues)) {
            String values = null;
            for (Object attributeValue : attributeValues) {
                if (values != null) {
                    values += FrameworkUtils.getMultiAttributeSeparator() + attributeValue;
                } else {
                    values = (String) attributeValue;
                }
            }
            claimsMap.put(attributeURI, values);
        }

        // check if values are set as complex values
        // NOTE: in carbon, we only support storing of type and
        // value of a multi-valued attribute
        List<Attribute> complexAttributeList = multiValAttribute.getAttributeValues();
        for (Attribute complexAttrib : complexAttributeList) {
            Map<String, Attribute> subAttributes =
                    ((ComplexAttribute) complexAttrib).getSubAttributesList();
            SimpleAttribute typeAttribute =
                    (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);
            String valueAttriubuteURI;
            // construct attribute URI
            String typeValue = null;
            if (typeAttribute != null) {
                typeValue = (String) typeAttribute.getValue();
                valueAttriubuteURI = attributeURI + "." + typeValue;
            } else {
                valueAttriubuteURI = attributeURI;
            }
            SimpleAttribute valueAttribute = null;
            if (attribute.getName().equals(SCIMConstants.UserSchemaConstants.ADDRESSES)) {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.UserSchemaConstants.FORMATTED_ADDRESS);
            } else {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);
            }
            if (valueAttribute != null && valueAttribute.getValue() != null) {
                // Put it in claims.
                claimsMap.put(valueAttriubuteURI,
                        AttributeUtil.getStringValueOfAttribute(valueAttribute.getValue(), valueAttribute.getType()));

            }

            boolean isComplexMultivaluedSupportEnabled = Boolean.parseBoolean(IdentityUtil.getProperty
                    (SCIM_COMPLEX_MULTIVALUED_ATTRIBUTE_SUPPORT_ENABLED));
            if (isComplexMultivaluedSupportEnabled) {
                Map<String, Attribute> otherAttributes = new HashMap<>(subAttributes);
                otherAttributes.remove(SCIMConstants.CommonSchemaConstants.TYPE);
                otherAttributes.remove(SCIMConstants.CommonSchemaConstants.VALUE);
                for (Map.Entry<String, Attribute> entry : otherAttributes.entrySet()) {
                    if (entry.getValue() instanceof SimpleAttribute) {
                        setClaimsForSimpleSubAttributeOfMultivaluedComplexAttribute(attributeURI, entry.getValue(),
                                claimsMap, typeValue);
                    }
                }
            }
        }
    }

    private static void setClaimsForSimpleSubAttributeOfMultivaluedComplexAttribute(String parentURI, Attribute
            attribute, Map<String, String> claimsMap, String type) throws CharonException {

        String attributeKey = attribute.getURI().replace(parentURI + ".", "");
        String attributeURI = parentURI + ADVANCED_ATTRIBUTE_IDENTIFIER + type + "." + attributeKey;
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(((SimpleAttribute) attribute).getValue(),
                    attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    /**
     * Set claim mapping for complex attribute.
     *
     * @param entry     Target attribute.
     * @param claimsMap A map containing claims and corresponding values to be set for the target attribute.
     */
    private static void setClaimsForComplexAttribute(Attribute entry, Map<String, String> claimsMap)
            throws CharonException {

        // Reading attributes list of the complex attribute.
        ComplexAttribute entryOfComplexAttribute = (ComplexAttribute) entry;
        Map<String, Attribute> entryAttributes;
        if (entryOfComplexAttribute.getSubAttributesList() != null &&
                MapUtils.isNotEmpty(entryOfComplexAttribute.getSubAttributesList())) {
            entryAttributes = entryOfComplexAttribute.getSubAttributesList();
            for (Attribute subEntry : entryAttributes.values()) {
                // attribute can only be simple attribute and that also in the extension schema only
                if (subEntry.getMultiValued()) {
                    setClaimsForMultivaluedAttribute(subEntry, claimsMap);
                } else {
                    setClaimsForSimpleAttribute(subEntry, claimsMap);
                }
            }
        }
    }
}
