<!--- 
	
	NAME:
	PWPolicy.cfc
	
	PURPOSE:
	Evaluate or generate password candidates against established criteria.
	
	URL:
	https://github.com/mrandrewmills/pwpolicy

	SOURCES/REFERENCES/ACKNOWLEDGEMENTS:
	* http://www.zytrax.com/tech/web/regex.htm (for RegEx syntaxes)
	* "Perfect Passwords" by Mark Burnett and Dave Kleiman
	* http://blogs.wsj.com/digits/2010/12/13/the-top-50-gawker-media-passwords/ 

--->

<cfcomponent output="false" hint="evaluate or generate password candidates against established criteria">

	<!--- Properties, for introspection --->
	<cfproperty name="minLength" displayname="minLength" hint="the minimum length required for the password" type="numeric" default="0" />
	<cfproperty name="minNumbers" displayname="minNumbers" hint="the minimum amount of numeric characters that are required in this password" type="numeric" default="0" />
	<cfproperty name="minUpper" displayname="minUpper" hint="minimum number of uppercase characters required in this password" type="numeric" default="0" />
	<cfproperty name="minSymbols" displayname="minSymbols" hint="minimum number of special characters that must appear in this password" type="numeric" default="0" />

	<cfproperty name="weakPWList" displayname="weakPWList" hint="comma-separated list of frequently used passwords that should be avoided" type="string" default="123456, password, lifehack, qwerty, abc123, 111111, monkey, consumer, 12345, 0, letmein, trustno1, dragon, 1234567, baseball, superman, iloveyou, gizmodo, sunshine,
1234, princess, starwars, whatever, shadow, cheese, 123123, nintendo, football, computer, f---you, 654321, blahblah, passw0rd, master, soccer, michael, 666666, jennifer, gawker, Password, jordan, pokemen, michelle, killer, pepper, welcome, batman, kotaku, internet">

	<cfproperty name="lowercase" displayname="lowercase" hint="the lower case letters allowed to be used in passwords" type="string" default="abcdefghijklmnopqrstuvwxyz">
	<cfproperty name="uppercase" displayname="uppercase" hint="the upper case letters allowed to be used in passwords" type="string" default="ABCDEFGHIJKLMNOPQRSTUVWXYZ">
	<cfproperty name="numbers" displayname="numbers" hint="the numbers allowed to be used in passwords" type="string" default="0123456789">
	<cfproperty name="symbols" displayname="symbols" hint="the symbol characters allowed to be used in passwords" type="string" default="~!@##$%^&*()_+{}|:<?>-`">
	<cfproperty name="forbidden" displayname="forbidden" hint="characters that must not be used in a password" type="string" default="" >

	<!--- pseudo-constructor --->
	<cfset VARIABLES.instance = StructNew()>
	<cfset VARIABLES.instance.minLength = 0>
	<cfset VARIABLES.instance.minNumbers = 0>
	<cfset VARIABLES.instance.minUpper = 0>
	<cfset VARIABLES.instance.minSymbols = 0>
	
	<!--- defaults to list of 50 most often used weak passwords discovered from Gawker 2010 breach --->
	<cfset VARIABLES.instance.weakPWList = "123456, password, lifehack, qwerty, abc123, 111111, monkey, consumer, 12345, 0, letmein, trustno1, dragon, 1234567, baseball, superman, iloveyou, gizmodo, sunshine,
1234, princess, starwars, whatever, shadow, cheese, 123123, nintendo, football, computer, f---you, 654321, blahblah, passw0rd, master, soccer, michael, 666666, jennifer, gawker, Password, jordan, pokemen, michelle, killer, pepper, welcome, batman, kotaku, internet">
	
	<!--- in five cases we specify what makes up lowercase, uppercase, numbers, etc. --->
	<cfset VARIABLES.instance.lowercase = "abcdefghijklmnopqrstuvwxyz">
	<cfset VARIABLES.instance.uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ">
	<cfset VARIABLES.instance.numbers = "0123456789">
	<cfset VARIABLES.instance.symbols = "~!@##$%^&*()_+{}=[]\;',./-">
	<cfset VARIABLES.instance.forbidden = "">

	<!--- constructor function --->
	<cffunction name="init" access="public" output="false" hint="constructor for the PWPolicy object" returntype="Any">
		<cfargument name="minLength" type="numeric" required="false" default="0" hint="minimum number of characters in a password">
		<cfargument name="minUpper" type="numeric" required="false" default="0" hint="minimum number of uppercase characters required in password">
		<cfargument name="minNumbers" type="numeric" required="false" default="0" hint="minimum number of numeric characters required in password">
		<cfargument name="minSymbols" type="numeric" required="false" default="0" hint="minimum number of symbol characters required in password">
		<cfargument name="weakPWList" type="string" hint="comma separated list of weak passwords that are not permitted" >
		<cfargument name="lowercase" type="string" hint="which characters count as lowercase in a password">
		<cfargument name="uppercase" type="string" hint="which characters count as uppercase in a password">
		<cfargument name="numbers" type="string" hint="which characters count as numbers in a password">	
		<cfargument name="symbols" type="string" hint="which characters count as symbols in a password">	
		<cfargument name="forbidden" type="string" hint="which characters cannot be used in a password">	
			
		<!--- let's initialize the easy properties first --->	
		<cfset setMinLength(ARGUMENTS.minLength)>
		<cfset setMinUpper(ARGUMENTS.minUpper)>
		<cfset setMinNumbers(ARGUMENTS.minNumbers)>
		<cfset setMinSymbols(ARGUMENTS.minSymbols)>
		
		<!--- initialize these only when they've been provided, otherwise leave them alone --->
		<cfif StructKeyExists(ARGUMENTS,"weakPWList")>
			<cfset setWeakPWList("#ARGUMENTS.weakPWList#")>
		</cfif>
		
		<cfif StructKeyExists(ARGUMENTS,"lowercase")>
			<cfset setLowercase("#ARGUMENTS.lowercase#")>
		</cfif>
		
		<cfif StructKeyExists(ARGUMENTS,"uppercase")>
			<cfset setUppercase("#ARGUMENTS.uppercase#")>
		</cfif>
		
		<cfif StructKeyExists(ARGUMENTS,"numbers")>
			<cfset setNumbers(newNumbers = "#ARGUMENTS.numbers#")>
		</cfif>	
		
		<cfif StructKeyExists(ARGUMENTS,"symbols")>
			<cfset setSymbols("#ARGUMENTS.symbols#")>
		</cfif> 
		
		<cfif StructKeyExists(ARGUMENTS,"forbidden")>
			<cfset setForbidden("#ARGUMENTS.forbidden#")>
		</cfif> 
	</cffunction>


	<!--- getters and setters, or accessors and mutators, if you prefer --->
	<cffunction name="getMinLength" access="public" output="false" returntype="numeric" hint="retrieves minimum number of characters required for a password">
		<cfreturn VARIABLES.instance.minLength />
	</cffunction>

	<cffunction name="setMinLength" access="public" output="false" returntype="void" hint="sets the minimum number of characters required for a password">
		<cfargument name="minLength" type="numeric" required="true" hint="must be an integer, 0 or greater" />

		<!--- if argument is less than zero, throw an error --->
		<cfif (ARGUMENTS.minLength LT 0)>
			<cfthrow errorcode="PWP-001" type="invalid argument" message="PWPolicy minimum length must be 0 or higher.">
		</cfif>
		
		<!--- if argument is not an integer, throw an error --->
		<cfif (Int(ARGUMENTS.minLength) NEQ ARGUMENTS.minLength)>
			<cfthrow errorcode="PWP-002" type="invalid argument" message="PWPolicy minimum length must be an integer.">
		</cfif>

		<cfset VARIABLES.instance.minLength = ARGUMENTS.minLength />

		<cfreturn />
	</cffunction>

	<cffunction name="getMinNumbers" access="public" output="false" returntype="numeric">
		<cfreturn VARIABLES.instance.minNumbers />
	</cffunction>

	<cffunction name="setMinNumbers" access="public" output="false" returntype="void">
		<cfargument name="minNumbers" type="numeric" required="true" />

	<!--- if argument is less than zero, throw an error --->
		<cfif (ARGUMENTS.minNumbers LT 0)>
			<cfthrow errorcode="PWP-001" type="invalid argument" message="PWPolicy minimum numbers must be 0 or higher.">
		</cfif>
		
		<!--- if argument is not an integer, throw an error --->
		<cfif (Int(ARGUMENTS.minNumbers) NEQ ARGUMENTS.minNumbers)>
			<cfthrow errorcode="PWP-002" type="invalid argument" message="PWPolicy minimum numbers must be an integer.">
		</cfif>

		<cfset VARIABLES.instance.minNumbers = ARGUMENTS.minNumbers />

		<cfreturn />
	</cffunction>
	
	<cffunction name="getMinSymbols" access="public" output="false" returntype="numeric">
		<cfreturn VARIABLES.instance.minSymbols />
	</cffunction>

	<cffunction name="setMinSymbols" access="public" output="false" returntype="void">
		<cfargument name="minSymbols" type="numeric" required="true" />

		<!--- if argument is less than zero, throw an error --->
		<cfif (ARGUMENTS.minSymbols LT 0)>
			<cfthrow errorcode="PWP-001" type="invalid argument" message="PWPolicy minimum symbols must be 0 or higher.">
		</cfif>
		
		<!--- if argument is not an integer, throw an error --->
		<cfif (Int(ARGUMENTS.minSymbols) NEQ ARGUMENTS.minSymbols)>
			<cfthrow errorcode="PWP-002" type="invalid argument" message="PWPolicy minimum symbols must be an integer.">
		</cfif>

		<cfset VARIABLES.instance.minSymbols = ARGUMENTS.minSymbols />

		<cfreturn />
	</cffunction>


	<cffunction name="getMinUpper" access="public" output="false" returntype="numeric">
		<cfreturn VARIABLES.instance.minUpper />
	</cffunction>

	<cffunction name="setMinUpper" access="public" output="false" returntype="void">
		<cfargument name="minUpper" type="numeric" required="true" />

		<!--- if argument is less than zero, throw an error --->
		<cfif (ARGUMENTS.minUpper LT 0)>
			<cfthrow errorcode="PWP-001" type="invalid argument" message="PWPolicy minimum uppercase must be 0 or higher.">
		</cfif>
		
		<!--- if argument is not an integer, throw an error --->
		<cfif (Int(ARGUMENTS.minUpper) NEQ ARGUMENTS.minUpper)>
			<cfthrow errorcode="PWP-002" type="invalid argument" message="PWPolicy minimum uppercase must be an integer.">
		</cfif>

		<cfset VARIABLES.instance.minUpper = ARGUMENTS.minUpper />

		<cfreturn />
	</cffunction>

	<cffunction name="setLowercase" access="public" output="false" returntype="void">
		<cfargument name="newLowercase" type="string" required="true">
		
		<cfset VARIABLES.instance.lowercase = ARGUMENTS.newLowercase />
		
	</cffunction>	
	
	<cffunction name="getLowercase" access="public" output="false" returntype="string">
		<cfreturn VARIABLES.instance.lowercase>
	</cffunction>
	
	<cffunction name="setUppercase" access="public" output="false" returntype="void">
		<cfargument name="newUppercase" type="string" required="true">
		
		<cfset VARIABLES.instance.uppercase = ARGUMENTS.newUppercase />
		
	</cffunction>	
	
	<cffunction name="getUppercase" access="public" output="false" returntype="string">
		<cfreturn VARIABLES.instance.uppercase>
	</cffunction>
	
	<cffunction name="setNumbers" access="public" output="false" returntype="void">
		<cfargument name="newNumbers" type="string" required="true">
		
		<cfset VARIABLES.instance.numbers = ARGUMENTS.newNumbers>
	</cffunction>
	
	<cffunction name="getNumbers" access="public" output="false" returntype="string">
		<cfreturn VARIABLES.instance.numbers>
	</cffunction>
	
	<cffunction name="setSymbols" access="public" output="false" returntype="void">
		<cfargument name="newSymbols" type="string" required="true">
		
		<cfset VARIABLES.instance.symbols = ARGUMENTS.newSymbols />
	</cffunction>
	
	<cffunction name="getSymbols" access="public" output="false" returntype="string">
		<cfreturn VARIABLES.instance.symbols>
	</cffunction>
	
	<cffunction name="setForbidden" access="public" output="false" returntype="void">
		<cfargument name="newForbidden" type="string" required="true">
		
		<cfset VARIABLES.instance.forbidden = ARGUMENTS.newForbidden />
	</cffunction>
	
	<cffunction name="getForbidden" access="public" output="false" returntype="string">
		<cfreturn VARIABLES.instance.forbidden>
	</cffunction>

	<cffunction name="setWeakPWList" access="public" output="false" returntype="void">
		<cfargument name="newWeakPWList" type="string" required="true">
		
		<cfset VARIABLES.instance.weakPWList = ARGUMENTS.newWeakPWList />
	</cffunction>
	
	<cffunction name="getWeakPWList" access="public" output="false" returntype="string">
		<cfreturn VARIABLES.instance.weakPWList>
	</cffunction>
	
	<cffunction name="check" hint="see if supplied password meets criteria set in properties" access="public" output="false" returntype="struct">
		<cfargument name="pwCandidate" displayName="passwordCandidate" type="string" hint="the password candidate you want to measure against your criteria" required="true" />
		
		<cfset var results = StructNew()>
		<cfset var RegExArray = ArrayNew(1)>
		<cfset var uppercase = "">
		<cfset var forbidden = "">
		<cfset var numbers = "">
		<cfset var symbols = "">

		<cfset results.valid = true>
		<cfset results.problems = ArrayNew(1)>

		<!--- is our password candidate less than our minimum length? --->
		<cfif Len(ARGUMENTS.pwCandidate) LT VARIABLES.instance.minLength>
			<cfset results.valid = false>
			<cfset ArrayAppend(results.problems,"TOO_SHORT") >
		</cfif>
		
		<!--- upper case? --->
		<cfset RegExArray = REMatch("[#escapeMetaChars(VARIABLES.instance.uppercase)#]",pwCandidate)>
		<cfif ArrayLen(RegExArray) LT VARIABLES.instance.minUpper>
			<cfset results.valid = false>
			<cfset ArrayAppend(results.problems,"TOO_FEW_UPPERCASE") >
		</cfif>
		
		<!--- numbers? --->
		<cfset RegExArray = REMatch("[#escapeMetaChars(VARIABLES.instance.numbers)#]",pwCandidate)>
		<cfif ArrayLen(RegExArray) LT VARIABLES.instance.minNumbers>
			<cfset results.valid = false>
			<cfset ArrayAppend(results.problems,"TOO_FEW_NUMBERS") >			
		</cfif>
				
		<!--- special characters? --->
		<cfset RegExArray = REMatch("[#escapeMetaChars(VARIABLES.instance.symbols)#]",pwCandidate)>
		<cfif ArrayLen(RegExArray) LT VARIABLES.instance.minSymbols>
			<cfset results.valid = false>
			<cfset ArrayAppend(results.problems,"TOO_FEW_SYMBOLS") >			
		</cfif>

		<!--- is it in the weak password list? --->
		<cfif (Find(ARGUMENTS.pwCandidate, VARIABLES.instance.weakPWList) GT 0)>
			<cfset results.valid = false>
			<cfset ArrayAppend(results.problems,"APPEARS_IN_WEAK_PASSWORD_LIST")>
		</cfif>
			
		<!--- any forbidden characters? --->
		<cfif (#VARIABLES.instance.forbidden# IS NOT "")>
			<cfset RegExArray = REMatch("[#escapeMetaChars(VARIABLES.instance.forbidden)#]",pwCandidate)>
			<cfif ArrayLen(RegExArray) GT 0>
				<cfset results.valid = false>
				<cfset ArrayAppend(results.problems,"FORBIDDEN_CHARACTERS") >			
			</cfif>
		</cfif>	
			
		<cfreturn results />
	</cffunction>	
	
	<cffunction name="generate" hint="create a random password based on criteria set in the component" access="public" output="false" returntype="string">
		
		<!--- Use var scope to limit our password Candidate to this function alone --->
		<cfset var pwCandidate = "">
		<cfset var pwIndex = "">
				
		<!--- upper case letters generated first --->
		<cfloop index="pwIndex" from="1" to=#VARIABLES.instance.minUpper#>
			<cfset pwCandidate = pwCandidate & #mid(VARIABLES.instance.uppercase, randrange(1,Len(VARIABLES.instance.uppercase)), 1)#>
		</cfloop>
		
		<!--- numbers generated next --->
		<cfloop index="pwIndex" from="1" to=#VARIABLES.instance.minNumbers#>
			<cfset pwCandidate = pwCandidate & #mid(VARIABLES.instance.numbers, randrange(1,Len(VARIABLES.instance.numbers)), 1)#>
		</cfloop>
		
		<!--- special characters generated next --->
		<cfloop index="pwIndex" from="1" to=#VARIABLES.instance.minSymbols#>
			<cfset pwCandidate = pwCandidate & #mid(VARIABLES.instance.symbols, randrange(1,Len(VARIABLES.instance.symbols)), 1)#>
		</cfloop>
		
		<!--- if we have not met minimum pw length, fill rest with lower case characters --->
		<cfloop condition="Len(pwCandidate) LT VARIABLES.instance.minLength">
			<cfset pwCandidate = pwCandidate & #chr(randrange(97,122))#>
		</cfloop>
		
		<cfset pwCandidate = Scramble(pwCandidate)>
		
		<cfreturn pwCandidate />
	</cffunction>
	
	<cffunction name="scramble" access="private" output="false" hint="for internal use only">
		<cfargument name="string" type="string" required="true">
	
		<cfloop index="y" from="1" to="#len(string)#">
			<cfset ARGUMENTS.String = swap(ARGUMENTS.string, y, randrange(1,len(string)))>
		</cfloop>
	
		<cfreturn ARGUMENTS.String />
	</cffunction>

	<cffunction name="swap" access="private" output="false" hint="for internal use only">
		<cfargument name="string" type="string" required="true">
		<cfargument name="posA" type="numeric" required="true">
		<cfargument name="posB" type="numeric" required="true">
	
		<cfset var tempArray = ArrayNew(1)>
		<cfset var resultString = "">
	
		<cfloop index="x" from="1" to="#len(string)#">
			<cfset tempArray[x] = mid(string, x, 1)>
		</cfloop>
	
		<cfset arraySwap(tempArray, ARGUMENTS.posA, ARGUMENTS.posB)>
	
		<cfloop index="x" from="1" to="#len(string)#">
			<cfset resultString = resultString & #tempArray[x]#>
		</cfloop>

		<cfreturn resultString />
	</cffunction>

	<cffunction name="escapeMetaChars" access="private" output="false" hint="for internal use only">
		<cfargument name="escapeThis" type="string" required="true" hint="string from which to escape regex metacharacters">

		<!--- escape sequences for backspaces, closing brackets, carets and hyphens --->
		<cfset ARGUMENTS.escapeThis = Replace(#ARGUMENTS.escapeThis#, "\", "\\", "All")>
		<cfset ARGUMENTS.escapeThis = Replace(#ARGUMENTS.escapeThis#, "]", "\]", "All")>
		<cfset ARGUMENTS.escapeThis = Replace(#ARGUMENTS.escapeThis#, "^", "\^", "All")>		
		<cfset ARGUMENTS.escapeThis = Replace(#ARGUMENTS.escapeThis#, "-", "\-", "All")>

		<cfreturn #ARGUMENTS.escapeThis#>	
	</cffunction>	
</cfcomponent>