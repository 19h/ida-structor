#pragma once
/// @file structor.hpp
/// @brief Master include header for Structor plugin
///
/// This header provides a convenient single-include for users of the Structor API.
/// It includes all public headers organized by module.
///
/// For finer-grained control, include specific module headers instead:
/// - structor/core/synth_types.hpp - Core data types
/// - structor/analysis/access_collector.hpp - Access pattern analysis
/// - structor/synthesis/layout_synthesizer.hpp - Structure synthesis
/// - structor/bindings/api.hpp - Public API

// ============================================================================
// Core Module
// ============================================================================
#include "structor/synth_types.hpp"
#include "structor/config.hpp"
#include "structor/utils.hpp"

// ============================================================================
// Analysis Module
// ============================================================================
#include "structor/access_collector.hpp"
#include "structor/vtable_detector.hpp"
#include "structor/cross_function_analyzer.hpp"
#include "structor/global_object_analyzer.hpp"

// ============================================================================
// Synthesis Module
// ============================================================================
#include "structor/layout_synthesizer.hpp"
#include "structor/structure_persistence.hpp"
#include "structor/type_propagator.hpp"
#include "structor/type_fixer.hpp"

// ============================================================================
// UI Module
// ============================================================================
#include "structor/ui_integration.hpp"
#include "structor/pseudocode_rewriter.hpp"

// ============================================================================
// Public API
// ============================================================================
#include "structor/api.hpp"
