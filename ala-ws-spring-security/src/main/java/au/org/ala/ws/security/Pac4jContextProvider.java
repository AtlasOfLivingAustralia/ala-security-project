/*
 * Copyright (C) 2025 Atlas of Living Australia
 * All Rights Reserved.
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 */

package au.org.ala.ws.security;

import org.pac4j.core.context.WebContext;

// TODO: move this and related classes into ala-security-project

/**
 * Provides a Pac4j Context via static methods or similar so that the client code need not take them as params.
 */
public interface Pac4jContextProvider {

    WebContext webContext();
}