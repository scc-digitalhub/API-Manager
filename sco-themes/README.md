# API-Manager
API Manager tools and themes

# Adding a New API Store Theme

## Folder structure of the API Store themes

- The default theme of the API Store is named wso2. You find it inside the <API-M_HOME>/repository/deployment/server/jaggeryapps/store/site/themes/wso2 folder.
- You can add a new theme as a main theme or a sub-theme:
		- A main theme is saved inside the <API-M_HOME>/repository/deployment/server/jaggeryapps/store/site/themes directory.
		- A sub theme is saved inside the <API-M_HOME>/repository/deployment/server/jaggeryapps/store/site/themes/<main-theme-directory>/subtheme directory.
- Notes:
		- As a sub-theme is saved inside a main theme, it needs to contain only the files that are different from the main theme. Any file that you add inside the sub-theme overrides the corresponding files in the main theme. The rest of the files are inherited from the main theme. 
		- Themes are located in the <API-M_HOME>/repository/deployment/server/jaggeryapps/store/site/themes folder. There are separate folders for each theme, typically by the name of the theme (e.g., wso2), inside the themes folder. In addition, there are CSS folders, which contain the CSS files of those themes, inside the individual theme folders. If you need to customize an existing theme, you need to change the corresponding CSS files.

## How to create a new theme and set it to the API Store: 

- 1.Writing a sub theme of the main theme.
- 2.Setting the new theme as the default theme.

### 1. Writing a sub theme of the main theme.

- 1.1 Download the default main theme, unzip it, and rename the folder according to the name of your new theme (e.g., ancient). Let's refer to this folder as <THEME_HOME>.

- 1.2 Make any changes you want to the theme. For example, make the following changes in the CSS styles in the <THEME_HOME>/css/custom.css file using a text editor and save:

		- Add the following code to change the color of the header to red.
			- 	header.header-default{
					background:red !important;
				}
		
		- Update the color given for the search box to #0be2e2.
			- 	.search-wrap>.form-control, .search-wrap .btn.wrap-input-right  {
					background-color: #0be2e2;
					border: 0px;
					color: #FFF;
					height: 40px;
					margin-top:-3px;
				}
		 
		- As you plan to upload the theme as a sub-theme of the default main theme, delete all the files in your <THEME_HOME> folder except the ones that you edited. The rest of the files are automatically applied from the main theme.

### 2. Setting the new theme as the default theme.

- 2.1 Save the <THEME_HOME> folder that contains the sub-theme of the main theme inside the <APIM_HOME>/repository/deployment/server/jaggeryapps/store/site/themes/wso2/subthemes folder. This makes your new theme a sub-theme of wso2. 

- 2.2 Open the <API-M_HOME>/repository/deployment/server/jaggeryapps/store/site/conf/site.json file, and add the following code to it. It specifies the base theme as wso2, which is overridden by the sub-theme ancient.
	- 	"theme" : {
			"base" : "wso2",
			"subtheme" : "ancient"
		}

- 2.3 Open the API Store. Note the new theme that is applied to it.
