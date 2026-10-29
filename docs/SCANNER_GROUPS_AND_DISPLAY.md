# Server Groups, Display and Progress


In **Scanner** or the wizard's Targets step, expand **+ Server groups (optional)**. Enter targets normally; discovery probing is optional. Choose the parsed targets that should receive a tag, enter a name, and use **+ Add group**. Use the searchable existing-group list to assign or remove further groups. Servers can belong to several groups. Grouping changes organization metadata; it does not select scan targets or change assessment verdicts.

In **Scan Library → Groups in the current fleet**, search hosts and filter by named groups or **Ungrouped**. Multiple selected group filters match any membership and combine with host search. Bulk changes apply only to explicitly selected hosts on the current page; changing pages or filters clears selection. Assemble or import scans first to populate the current fleet. Renaming a group preserves memberships; deleting one removes its tag while keeping the servers.

Memberships travel with saved scan metadata, imports, fleet assembly and JSON/CSV/Excel/HTML outputs. The local registry is `~/.vcf-readiness/server_groups.json`. Stable hardware identity is preferred over display names; a reused BMC address does not transfer a known server's membership to different identified hardware. A server with no usable hardware identifier can initially be matched only to its target address. Explicit local removals take precedence when older observations are imported. Obfuscated exports replace private group labels while retaining membership relationships.

Use the top-right **Compact** toggle to switch between comfortable and compact table spacing. Its pressed state is also shown with an underline. The adjacent sun/moon button displays the current **Light** or **Dark** mode; click it to switch themes. Generated reports keep these controls available above every tab, and the Compact toggle stays synchronized with the Detailed Inventory density selector. Preferences persist where browser storage is available. Reports continue to work offline. Help uses left-aligned content and section navigation; on narrow screens expand its **On this page** navigation.

The scanner progress bar measures **hosts processed in the current pass**, including hosts with collection failures. It is not a count of healthy hosts or an estimate of elapsed runtime. Retry passes are labelled separately. Report preparation, cancellation and reconnect states have their own messages.

VDT collection shows stages with an indeterminate indicator while duration is unknown. Its setup step number is separate from collection progress. Retrieved evidence, findings and remote cleanup outcomes remain distinct; review any retained temporary-directory message. Operations with no measurable total show activity and elapsed time without inventing a completion percentage. Collection logs and detailed evidence remain available in expandable sections.


## Local icons and preserved data

Scanner and HTML report icons are always enabled and bundled locally. The old emoji display controls are retired; older saved settings no longer suppress icons or strip text. Labels stay visible beside icons. NVMe/SSD/HDD icons use observed transport/media without implying readiness or support. Diagrams and crowded table columns retain their existing layout. Group names, input values, copied paths, code and text exports preserve original Unicode characters.
