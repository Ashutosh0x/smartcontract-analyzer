use crate::context::WorkspaceContext;

pub fn print_inheritance(ctx: &WorkspaceContext) -> String {
    let mut output = String::from("# Inheritance Graph\n\n");
    output.push_str("```mermaid\ngraph TD\n");
    for contract in &ctx.contracts {
        for base in &contract.bases {
            output.push_str(&format!("    {}[{}] --> {}[{}]\n", contract.name, contract.name, base, base));
        }
        if contract.bases.is_empty() {
            output.push_str(&format!("    {}[{}]\n", contract.name, contract.name));
        }
    }
    output.push_str("```\n");
    output
}

pub fn print_functions(ctx: &WorkspaceContext) -> String {
    let mut output = String::from("# Function Summary\n\n");
    output.push_str("| Contract | Function | Visibility | Mutability | Modifiers |\n");
    output.push_str("|----------|----------|-----------|------------|-----------|\n");
    for func in &ctx.functions {
        if func.is_constructor || func.is_receive || func.is_fallback {
            continue; // skip special functions in summary
        }
        let contract_name = ctx.contracts.get(func.contract_idx)
            .map(|c| c.name.as_str()).unwrap_or("?");
        let vis = format!("{:?}", func.visibility);
        let mut_str = format!("{:?}", func.mutability);
        let mods = if func.modifiers.is_empty() { "-".to_string() } else { func.modifiers.join(", ") };
        output.push_str(&format!("| {} | {} | {} | {} | {} |\n",
            contract_name, func.name, vis, mut_str, mods));
    }
    output
}

pub fn print_state_variables(ctx: &WorkspaceContext) -> String {
    let mut output = String::from("# State Variables\n\n");
    output.push_str("| Contract | Variable | Type | Visibility | Constant | Immutable | Initialized |\n");
    output.push_str("|----------|----------|------|-----------|----------|-----------|-------------|\n");
    for var in &ctx.state_variables {
        let contract_name = ctx.contracts.get(var.contract_idx)
            .map(|c| c.name.as_str()).unwrap_or("?");
        output.push_str(&format!("| {} | {} | {} | {:?} | {} | {} | {} |\n",
            contract_name, var.name, var.type_name,
            var.visibility, var.is_constant, var.is_immutable, var.is_initialized));
    }
    output
}

pub fn print_external_calls(ctx: &WorkspaceContext) -> String {
    let mut output = String::from("# External Calls\n\n");
    output.push_str("| Contract | Function | Call Type | Target |\n");
    output.push_str("|----------|----------|----------|--------|\n");
    for func in &ctx.functions {
        let contract_name = ctx.contracts.get(func.contract_idx)
            .map(|c| c.name.as_str()).unwrap_or("?");
        for call in &func.external_calls {
            output.push_str(&format!("| {} | {} | {:?} | {} |\n",
                contract_name, func.name, call.call_type, call.target));
        }
    }
    output
}

pub fn print_permissions(ctx: &WorkspaceContext) -> String {
    let mut output = String::from("# Access Control Map\n\n");
    output.push_str("| Contract | Function | Visibility | Access Modifiers |\n");
    output.push_str("|----------|----------|-----------|-----------------|\n");
    for func in &ctx.functions {
        let contract_name = ctx.contracts.get(func.contract_idx)
            .map(|c| c.name.as_str()).unwrap_or("?");
        let access_mods: Vec<&String> = func.modifiers.iter()
            .filter(|m| m.contains("only") || m.contains("Only") || m.contains("auth") || m.contains("require"))
            .collect();
        let access_str = if access_mods.is_empty() {
            if func.visibility == crate::context::Visibility::External || func.visibility == crate::context::Visibility::Public {
                "UNRESTRICTED".to_string()
            } else {
                format!("{:?}", func.visibility)
            }
        } else {
            access_mods.iter().map(|m| m.as_str()).collect::<Vec<_>>().join(", ")
        };
        if func.visibility == crate::context::Visibility::External || func.visibility == crate::context::Visibility::Public {
            output.push_str(&format!("| {} | {} | {:?} | {} |\n",
                contract_name, func.name, func.visibility, access_str));
        }
    }
    output
}
